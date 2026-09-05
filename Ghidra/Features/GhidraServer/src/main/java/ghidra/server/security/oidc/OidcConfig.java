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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.Set;

/**
 * OIDC provider settings loaded from a properties file. The file must not
 * contain client secrets; device-code clients are public.
 */
public final class OidcConfig {

	public static final String DEFAULT_USERNAME_CLAIM = "preferred_username";
	public static final String DEFAULT_USERNAME_CLAIM_FALLBACKS = "email,sub";
	public static final String DEFAULT_USERNAME_TRANSFORM = "lowercase";
	public static final String DEFAULT_SCOPES = "openid profile";
	public static final int DEFAULT_LOGIN_TIMEOUT_SECONDS = 900;
	public static final int DEFAULT_MAX_TOKEN_AGE_SECONDS = 600;
	public static final int DEFAULT_CLOCK_SKEW_SECONDS = 60;

	private final String issuer;
	private final String clientId;
	private final String usernameClaim;
	private final List<String> usernameClaimFallbacks;
	private final String scopes;
	private final int loginTimeoutSeconds;
	private final int maxTokenAgeSeconds;
	private final int clockSkewSeconds;
	private final Set<String> allowedSigningAlgs;
	private final String audience;
	private final String jwksUri;
	private final File jwksFile;
	private final String deviceAuthorizationEndpoint;
	private final String tokenEndpoint;
	private final String tenantId;
	private final String hostedDomain;
	private final String displayName;

	private OidcConfig(String issuer, String clientId, String usernameClaim,
			List<String> usernameClaimFallbacks, String scopes, int loginTimeoutSeconds,
			int maxTokenAgeSeconds, int clockSkewSeconds, Set<String> allowedSigningAlgs,
			String audience, String jwksUri, File jwksFile, String deviceAuthorizationEndpoint,
			String tokenEndpoint, String tenantId, String hostedDomain, String displayName) {
		this.issuer = issuer;
		this.clientId = clientId;
		this.usernameClaim = usernameClaim;
		this.usernameClaimFallbacks = usernameClaimFallbacks;
		this.scopes = scopes;
		this.loginTimeoutSeconds = loginTimeoutSeconds;
		this.maxTokenAgeSeconds = maxTokenAgeSeconds;
		this.clockSkewSeconds = clockSkewSeconds;
		this.allowedSigningAlgs = allowedSigningAlgs;
		this.audience = audience;
		this.jwksUri = jwksUri;
		this.jwksFile = jwksFile;
		this.deviceAuthorizationEndpoint = deviceAuthorizationEndpoint;
		this.tokenEndpoint = tokenEndpoint;
		this.tenantId = tenantId;
		this.hostedDomain = hostedDomain;
		this.displayName = displayName;
	}

	/**
	 * Load and validate an OIDC properties file.
	 *
	 * @param configFile OIDC config file
	 * @return parsed configuration
	 * @throws IOException if the file cannot be read
	 * @throws IllegalArgumentException if required values are missing or invalid
	 */
	public static OidcConfig load(File configFile) throws IOException {
		if (configFile == null) {
			throw new IllegalArgumentException("OIDC config file not specified");
		}
		if (!configFile.isFile()) {
			throw new IllegalArgumentException(
				"OIDC config file does not exist or is not file: " + configFile.getAbsolutePath());
		}

		Properties properties = new Properties();
		try (InputStream in = new FileInputStream(configFile)) {
			properties.load(in);
		}

		String issuer = requireHttpsUrl(required(properties, "issuer"), "issuer");
		String clientId = required(properties, "clientId");
		String usernameClaim =
			optional(properties, "usernameClaim", DEFAULT_USERNAME_CLAIM);
		List<String> fallbacks = splitComma(
			optional(properties, "usernameClaimFallbacks", DEFAULT_USERNAME_CLAIM_FALLBACKS));
		String transform =
			optional(properties, "usernameTransform", DEFAULT_USERNAME_TRANSFORM);
		if (!DEFAULT_USERNAME_TRANSFORM.equalsIgnoreCase(transform)) {
			throw new IllegalArgumentException(
				"usernameTransform must be lowercase");
		}
		String scopes = normalizeScopes(optional(properties, "scopes", DEFAULT_SCOPES));
		int loginTimeoutSeconds = parsePositiveInt(properties, "loginTimeoutSeconds",
			DEFAULT_LOGIN_TIMEOUT_SECONDS);
		int maxTokenAgeSeconds = parsePositiveInt(properties, "maxTokenAgeSeconds",
			DEFAULT_MAX_TOKEN_AGE_SECONDS);
		int clockSkewSeconds = parseNonNegativeInt(properties, "clockSkewSeconds",
			DEFAULT_CLOCK_SKEW_SECONDS);
		Set<String> allowedSigningAlgs = parseAllowedAlgs(optional(properties, "allowedSigningAlgs",
			String.join(",", OidcIdTokenValidator.DEFAULT_ALLOWED_SIGNING_ALGS)));
		String audience = optional(properties, "audience", clientId);
		if (isBlank(audience)) {
			audience = clientId;
		}
		String jwksUri = optionalUrl(properties, "jwksUri");
		File jwksFile = optionalFile(properties, "jwksFile", configFile.getParentFile());
		String deviceAuthorizationEndpoint =
			optionalUrl(properties, "deviceAuthorizationEndpoint");
		String tokenEndpoint = optionalUrl(properties, "tokenEndpoint");
		String tenantId = blankToNull(properties.getProperty("tenantId"));
		String hostedDomain = blankToNull(properties.getProperty("hostedDomain"));
		String displayName = blankToNull(properties.getProperty("displayName"));

		return new OidcConfig(issuer, clientId, usernameClaim, fallbacks, scopes,
			loginTimeoutSeconds, maxTokenAgeSeconds, clockSkewSeconds, allowedSigningAlgs,
			audience, jwksUri, jwksFile, deviceAuthorizationEndpoint, tokenEndpoint, tenantId,
			hostedDomain, displayName);
	}

	public String getIssuer() {
		return issuer;
	}

	public String getClientId() {
		return clientId;
	}

	public String getUsernameClaim() {
		return usernameClaim;
	}

	public List<String> getUsernameClaimFallbacks() {
		return usernameClaimFallbacks;
	}

	public String getScopes() {
		return scopes;
	}

	public int getLoginTimeoutSeconds() {
		return loginTimeoutSeconds;
	}

	public int getMaxTokenAgeSeconds() {
		return maxTokenAgeSeconds;
	}

	public int getClockSkewSeconds() {
		return clockSkewSeconds;
	}

	public Set<String> getAllowedSigningAlgs() {
		return allowedSigningAlgs;
	}

	public String getAudience() {
		return audience;
	}

	public String getJwksUri() {
		return jwksUri;
	}

	public File getJwksFile() {
		return jwksFile;
	}

	public String getDeviceAuthorizationEndpoint() {
		return deviceAuthorizationEndpoint;
	}

	public String getTokenEndpoint() {
		return tokenEndpoint;
	}

	public String getTenantId() {
		return tenantId;
	}

	public String getHostedDomain() {
		return hostedDomain;
	}

	public String getDisplayName() {
		return displayName;
	}

	/**
	 * {@return true if discovery can be skipped because JWKS and both endpoints
	 * are configured locally}
	 */
	public boolean isAirGap() {
		return jwksFile != null && deviceAuthorizationEndpoint != null && tokenEndpoint != null;
	}

	static String requireHttpsUrl(String value, String name) {
		URI uri = parseUri(value, name);
		String scheme = uri.getScheme();
		if ("https".equalsIgnoreCase(scheme)) {
			return stripTrailingSlash(value.trim());
		}
		if ("http".equalsIgnoreCase(scheme) && isLoopbackHost(uri.getHost())) {
			return stripTrailingSlash(value.trim());
		}
		throw new IllegalArgumentException(name + " must be an https URL");
	}

	static boolean isLoopbackHost(String host) {
		if (host == null || host.isBlank()) {
			return false;
		}
		try {
			return InetAddress.getByName(host).isLoopbackAddress();
		}
		catch (UnknownHostException e) {
			return false;
		}
	}

	static String stripTrailingSlash(String value) {
		if (value.length() > 1 && value.endsWith("/")) {
			return value.substring(0, value.length() - 1);
		}
		return value;
	}

	private static URI parseUri(String value, String name) {
		URI uri;
		try {
			uri = URI.create(value.trim());
		}
		catch (IllegalArgumentException e) {
			throw new IllegalArgumentException(name + " is not a valid URL");
		}
		if (uri.getScheme() == null || uri.getHost() == null) {
			throw new IllegalArgumentException(name + " is not a valid URL");
		}
		return uri;
	}

	private static String required(Properties properties, String key) {
		String value = blankToNull(properties.getProperty(key));
		if (value == null) {
			throw new IllegalArgumentException("OIDC config missing required property: " + key);
		}
		return value;
	}

	private static String optional(Properties properties, String key, String defaultValue) {
		String value = blankToNull(properties.getProperty(key));
		return value != null ? value : defaultValue;
	}

	private static String optionalUrl(Properties properties, String key) {
		String value = blankToNull(properties.getProperty(key));
		if (value == null) {
			return null;
		}
		return requireHttpsUrl(value, key);
	}

	private static File optionalFile(Properties properties, String key, File relativeTo) {
		String value = blankToNull(properties.getProperty(key));
		if (value == null) {
			return null;
		}
		File file = new File(value);
		if (!file.isAbsolute() && relativeTo != null) {
			file = new File(relativeTo, value);
		}
		if (!file.isFile()) {
			throw new IllegalArgumentException(
				key + " does not exist or is not a file: " + file.getAbsolutePath());
		}
		return file;
	}

	private static int parsePositiveInt(Properties properties, String key, int defaultValue) {
		int value = parseInt(properties, key, defaultValue);
		if (value <= 0) {
			throw new IllegalArgumentException(key + " must be > 0");
		}
		return value;
	}

	private static int parseNonNegativeInt(Properties properties, String key, int defaultValue) {
		int value = parseInt(properties, key, defaultValue);
		if (value < 0) {
			throw new IllegalArgumentException(key + " must be >= 0");
		}
		return value;
	}

	private static int parseInt(Properties properties, String key, int defaultValue) {
		String raw = blankToNull(properties.getProperty(key));
		if (raw == null) {
			return defaultValue;
		}
		try {
			return Integer.parseInt(raw);
		}
		catch (NumberFormatException e) {
			throw new IllegalArgumentException(key + " is not a valid integer");
		}
	}

	private static List<String> splitComma(String raw) {
		if (raw == null || raw.isBlank()) {
			return List.of();
		}
		List<String> values = new ArrayList<>();
		for (String part : raw.split(",")) {
			String trimmed = part.trim();
			if (!trimmed.isEmpty()) {
				values.add(trimmed);
			}
		}
		return Collections.unmodifiableList(values);
	}

	private static Set<String> parseAllowedAlgs(String raw) {
		List<String> names = splitComma(raw);
		if (names.isEmpty()) {
			throw new IllegalArgumentException("allowedSigningAlgs must not be empty");
		}
		Set<String> algs = new LinkedHashSet<>(names);
		for (String alg : algs) {
			if ("none".equalsIgnoreCase(alg) || alg.toUpperCase(Locale.ROOT).startsWith("HS")) {
				throw new IllegalArgumentException("Signing algorithm not allowed: " + alg);
			}
		}
		return Collections.unmodifiableSet(algs);
	}

	private static String normalizeScopes(String raw) {
		List<String> scopes = new ArrayList<>();
		if (raw != null) {
			for (String part : raw.trim().split("\\s+")) {
				if (!part.isEmpty() && !scopes.contains(part)) {
					scopes.add(part);
				}
			}
		}
		if (!scopes.contains("openid")) {
			scopes.add(0, "openid");
		}
		return String.join(" ", scopes);
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
}
