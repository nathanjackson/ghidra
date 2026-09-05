/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.server.security.oidc;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.nimbusds.jose.util.JSONObjectUtils;

import ghidra.net.HttpClients;

/**
 * Fetches and caches OpenID Provider metadata over HTTPS GET.
 */
public final class OidcDiscoveryClient {

	static final Logger log = LogManager.getLogger(OidcDiscoveryClient.class);

	static final int HTTP_TIMEOUT_SECONDS = 10;
	static final long CACHE_TTL_MS = 60 * 60 * 1000L;

	private final HttpClient httpClient;
	private final long cacheTtlMs;

	private volatile CachedMetadata cache;

	public OidcDiscoveryClient() throws IOException {
		this(HttpClients.newHttpClientBuilder()
				.connectTimeout(Duration.ofSeconds(HTTP_TIMEOUT_SECONDS))
				.build(),
			CACHE_TTL_MS);
	}

	OidcDiscoveryClient(HttpClient httpClient) {
		this(httpClient, CACHE_TTL_MS);
	}

	OidcDiscoveryClient(HttpClient httpClient, long cacheTtlMs) {
		if (httpClient == null) {
			throw new IllegalArgumentException("httpClient is required");
		}
		this.httpClient = httpClient;
		this.cacheTtlMs = cacheTtlMs;
	}

	/**
	 * Return cached metadata for {@code issuer}, fetching when missing or stale.
	 *
	 * @param issuer OIDC issuer identifier
	 * @return provider metadata
	 * @throws IOException if discovery cannot be retrieved or parsed
	 */
	public ProviderMetadata getMetadata(String issuer) throws IOException {
		if (issuer == null || issuer.isBlank()) {
			throw new IllegalArgumentException("issuer is required");
		}
		String normalizedIssuer = OidcConfig.stripTrailingSlash(issuer.trim());
		CachedMetadata cached = cache;
		long now = System.currentTimeMillis();
		if (cached != null && normalizedIssuer.equals(cached.issuer) &&
			now - cached.fetchedAtMs < cacheTtlMs) {
			return cached.metadata;
		}
		synchronized (this) {
			cached = cache;
			now = System.currentTimeMillis();
			if (cached != null && normalizedIssuer.equals(cached.issuer) &&
				now - cached.fetchedAtMs < cacheTtlMs) {
				return cached.metadata;
			}
			ProviderMetadata metadata = fetch(normalizedIssuer);
			cache = new CachedMetadata(normalizedIssuer, metadata, now);
			return metadata;
		}
	}

	/**
	 * Validate that discovery metadata is usable for the device-code grant.
	 * Missing {@code none} in {@code token_endpoint_auth_methods_supported} is a
	 * warning, not a startup failure: public device-code clients do not
	 * authenticate to the token endpoint, and some providers (Entra ID) omit
	 * {@code none} even for public apps.
	 *
	 * @param metadata discovery document
	 * @param allowedSigningAlgs configured JWS allowlist
	 * @return intersection of discovery signing algs and {@code allowedSigningAlgs},
	 *         or {@code allowedSigningAlgs} when discovery omitted the list
	 * @throws IOException if required device-code metadata is missing or incompatible
	 */
	public static Set<String> validateDeviceCodeSupport(ProviderMetadata metadata,
			Collection<String> allowedSigningAlgs) throws IOException {
		if (metadata == null) {
			throw new IOException("OIDC discovery metadata is required");
		}
		if (isBlank(metadata.deviceAuthorizationEndpoint)) {
			throw new IOException(
				"OIDC discovery did not advertise device_authorization_endpoint. " +
					"Register a public/native client with device authorization enabled.");
		}
		requireHttpsDiscoveryUrl(metadata.deviceAuthorizationEndpoint,
			"device_authorization_endpoint");
		if (isBlank(metadata.tokenEndpoint)) {
			throw new IOException("OIDC discovery did not advertise token_endpoint");
		}
		requireHttpsDiscoveryUrl(metadata.tokenEndpoint, "token_endpoint");
		if (isBlank(metadata.jwksUri)) {
			throw new IOException("OIDC discovery did not advertise jwks_uri");
		}
		requireHttpsDiscoveryUrl(metadata.jwksUri, "jwks_uri", false);

		if (metadata.tokenEndpointAuthMethodsSupported != null &&
			!metadata.tokenEndpointAuthMethodsSupported.isEmpty() &&
			!containsIgnoreCase(metadata.tokenEndpointAuthMethodsSupported, "none")) {
			// Entra and some other public-client metadata omit none even though
			// device-code token POSTs are unauthenticated. v1 has no client secret.
			log.warn(
				"OIDC token_endpoint_auth_methods_supported does not include none; " +
					"continuing because device-code public clients do not authenticate " +
					"to the token endpoint");
		}

		Set<String> allowed = allowedSigningAlgs == null ? Set.of()
				: new LinkedHashSet<>(allowedSigningAlgs);
		if (metadata.idTokenSigningAlgValuesSupported == null ||
			metadata.idTokenSigningAlgValuesSupported.isEmpty()) {
			return Collections.unmodifiableSet(allowed);
		}
		Set<String> intersection = intersectIgnoreCase(metadata.idTokenSigningAlgValuesSupported,
			allowed);
		if (intersection.isEmpty()) {
			throw new IOException(
				"No overlap between allowedSigningAlgs and id_token_signing_alg_values_supported");
		}
		return Collections.unmodifiableSet(intersection);
	}

	private ProviderMetadata fetch(String issuer) throws IOException {
		URI discoveryUri = URI.create(issuer + "/.well-known/openid-configuration");
		HttpRequest request = HttpRequest.newBuilder(discoveryUri)
				.timeout(Duration.ofSeconds(HTTP_TIMEOUT_SECONDS))
				.header("Accept", "application/json")
				.GET()
				.build();
		HttpResponse<String> response;
		try {
			response = httpClient.send(request, BodyHandlers.ofString(StandardCharsets.UTF_8));
		}
		catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			throw new IOException("OIDC discovery interrupted", e);
		}
		catch (IOException e) {
			throw new IOException("OIDC discovery failed for issuer " + issuer, e);
		}
		if (response.statusCode() != 200) {
			throw new IOException("OIDC discovery failed: HTTP " + response.statusCode());
		}
		String body = response.body();
		if (body == null || body.isBlank()) {
			throw new IOException("OIDC discovery document is empty");
		}

		Map<String, Object> json;
		try {
			json = JSONObjectUtils.parse(body);
		}
		catch (ParseException e) {
			throw new IOException("OIDC discovery document is not valid JSON", e);
		}

		try {
			String discoveredIssuer = JSONObjectUtils.getString(json, "issuer");
			if (isBlank(discoveredIssuer) ||
				!OidcConfig.stripTrailingSlash(discoveredIssuer).equals(issuer)) {
				throw new IOException("OIDC discovery issuer mismatch");
			}
			return new ProviderMetadata(issuer,
				blankToNull(JSONObjectUtils.getString(json, "device_authorization_endpoint")),
				blankToNull(JSONObjectUtils.getString(json, "token_endpoint")),
				blankToNull(JSONObjectUtils.getString(json, "jwks_uri")),
				optionalStringList(json, "token_endpoint_auth_methods_supported"),
				optionalStringList(json, "id_token_signing_alg_values_supported"));
		}
		catch (ParseException e) {
			throw new IOException("OIDC discovery document is missing required fields", e);
		}
	}

	private static List<String> optionalStringList(Map<String, Object> json, String key)
			throws ParseException {
		if (!json.containsKey(key) || json.get(key) == null) {
			return null;
		}
		List<String> values = JSONObjectUtils.getStringList(json, key);
		if (values == null) {
			return null;
		}
		List<String> copy = new ArrayList<>();
		for (String value : values) {
			if (value != null && !value.isBlank()) {
				copy.add(value.trim());
			}
		}
		return Collections.unmodifiableList(copy);
	}

	private static Set<String> intersectIgnoreCase(Collection<String> left,
			Collection<String> right) {
		Set<String> result = new LinkedHashSet<>();
		for (String candidate : left) {
			if (containsIgnoreCase(right, candidate)) {
				result.add(candidate);
			}
		}
		return result;
	}

	private static boolean containsIgnoreCase(Collection<String> values, String expected) {
		for (String value : values) {
			if (expected.equalsIgnoreCase(value)) {
				return true;
			}
		}
		return false;
	}

	private static void requireHttpsDiscoveryUrl(String value, String name) throws IOException {
		requireHttpsDiscoveryUrl(value, name, true);
	}

	private static void requireHttpsDiscoveryUrl(String value, String name,
			boolean allowLoopbackHttp) throws IOException {
		try {
			OidcConfig.requireHttpsUrl(value, name, allowLoopbackHttp);
		}
		catch (IllegalArgumentException e) {
			throw new IOException(e.getMessage(), e);
		}
	}

	private static String blankToNull(String value) {
		if (value == null) {
			return null;
		}
		String trimmed = value.trim();
		return trimmed.isEmpty() ? null : trimmed;
	}

	private static boolean isBlank(String value) {
		return value == null || value.trim().isEmpty();
	}

	public static final class ProviderMetadata {
		public final String issuer;
		public final String deviceAuthorizationEndpoint;
		public final String tokenEndpoint;
		public final String jwksUri;
		public final List<String> tokenEndpointAuthMethodsSupported;
		public final List<String> idTokenSigningAlgValuesSupported;

		public ProviderMetadata(String issuer, String deviceAuthorizationEndpoint,
				String tokenEndpoint, String jwksUri,
				List<String> tokenEndpointAuthMethodsSupported,
				List<String> idTokenSigningAlgValuesSupported) {
			this.issuer = issuer;
			this.deviceAuthorizationEndpoint = deviceAuthorizationEndpoint;
			this.tokenEndpoint = tokenEndpoint;
			this.jwksUri = jwksUri;
			this.tokenEndpointAuthMethodsSupported = tokenEndpointAuthMethodsSupported;
			this.idTokenSigningAlgValuesSupported = idTokenSigningAlgValuesSupported;
		}
	}

	private static final class CachedMetadata {
		private final String issuer;
		private final ProviderMetadata metadata;
		private final long fetchedAtMs;

		private CachedMetadata(String issuer, ProviderMetadata metadata, long fetchedAtMs) {
			this.issuer = issuer;
			this.metadata = metadata;
			this.fetchedAtMs = fetchedAtMs;
		}
	}
}
