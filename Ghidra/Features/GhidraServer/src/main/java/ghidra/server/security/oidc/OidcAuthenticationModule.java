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
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.text.ParseException;
import java.util.Collection;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;

import ghidra.framework.remote.OidcAuthenticationCallback;
import ghidra.server.UserManager;
import ghidra.server.security.AuthenticationModule;
import ghidra.server.security.oidc.OidcDiscoveryClient.ProviderMetadata;
import ghidra.server.security.oidc.OidcIdTokenValidator.OidcIdTokenException;
import ghidra.server.security.oidc.OidcLoginChallengeStore.IssuedChallenge;

/**
 * Authenticates Ghidra Server users with an OIDC ID token obtained by the
 * client via the device-code grant.
 */
public class OidcAuthenticationModule implements AuthenticationModule {

	static final Logger log = LogManager.getLogger(OidcAuthenticationModule.class);

	private final OidcConfig config;
	private final OidcUsernameMapper usernameMapper;
	private final OidcLoginChallengeStore challengeStore;
	private final OidcDiscoveryClient discoveryClient;
	private final JWKSource<SecurityContext> jwkSource;
	private final Set<String> allowedSigningAlgs;

	private volatile String deviceAuthorizationEndpoint;
	private volatile String tokenEndpoint;

	/**
	 * Construct an OIDC authentication module from a properties file.
	 *
	 * @param oidcConfigFile OIDC configuration file
	 * @throws IOException if discovery fails or the JWKS source cannot be created
	 * @throws IllegalArgumentException if the file is missing or invalid
	 */
	public OidcAuthenticationModule(File oidcConfigFile) throws IOException {
		this(oidcConfigFile, null);
	}

	OidcAuthenticationModule(File oidcConfigFile, HttpClient httpClient) throws IOException {
		this(OidcConfig.load(oidcConfigFile), httpClient);
	}

	OidcAuthenticationModule(OidcConfig config, HttpClient httpClient) throws IOException {
		if (config == null) {
			throw new IllegalArgumentException("OIDC config is required");
		}
		this.config = config;
		this.usernameMapper = new OidcUsernameMapper(config);
		this.challengeStore = new OidcLoginChallengeStore(config.getLoginTimeoutSeconds());

		if (config.isAirGap()) {
			this.discoveryClient = null;
			this.deviceAuthorizationEndpoint = config.getDeviceAuthorizationEndpoint();
			this.tokenEndpoint = config.getTokenEndpoint();
			this.allowedSigningAlgs = config.getAllowedSigningAlgs();
			this.jwkSource = fileJwkSource(config.getJwksFile());
			validateJwksFileKeys(config.getJwksFile(), this.allowedSigningAlgs);
		}
		else {
			this.discoveryClient = httpClient == null ? new OidcDiscoveryClient()
					: new OidcDiscoveryClient(httpClient);
			ProviderMetadata metadata = discoveryClient.getMetadata(config.getIssuer());
			this.allowedSigningAlgs =
				OidcDiscoveryClient.validateDeviceCodeSupport(metadata,
					config.getAllowedSigningAlgs());
			applyEndpoints(metadata);
			if (config.getJwksFile() != null) {
				this.jwkSource = fileJwkSource(config.getJwksFile());
				validateJwksFileKeys(config.getJwksFile(), this.allowedSigningAlgs);
			}
			else {
				String jwksUri = firstNonBlank(config.getJwksUri(), metadata.jwksUri);
				this.jwkSource =
					OidcIdTokenValidator.createRemoteJwkSource(URI.create(jwksUri).toURL());
			}
		}
	}

	@Override
	public boolean isNameCallbackAllowed() {
		return false;
	}

	@Override
	public boolean anonymousCallbacksAllowed() {
		return true;
	}

	@Override
	public Callback[] getAuthenticationCallbacks() {
		ResolvedEndpoints endpoints = resolveEndpoints();
		IssuedChallenge issued;
		try {
			issued = challengeStore.issue();
		}
		catch (IllegalStateException e) {
			throw new RuntimeException(e.getMessage(), e);
		}
		return new Callback[] { new OidcAuthenticationCallback(config.getIssuer(),
			config.getClientId(), endpoints.deviceAuthorizationEndpoint, endpoints.tokenEndpoint,
			config.getScopes(), issued.nonce, issued.loginChallenge,
			config.getLoginTimeoutSeconds(), config.getDisplayName()) };
	}

	@Override
	public String authenticate(UserManager userMgr, Subject subject, Callback[] callbacks)
			throws LoginException {
		OidcAuthenticationCallback oidcCallback =
			AuthenticationModule.getFirstCallbackOfType(OidcAuthenticationCallback.class,
				callbacks);
		if (oidcCallback == null) {
			throw new FailedLoginException("OIDC authentication callback required");
		}
		String idToken = oidcCallback.getIdToken();
		oidcCallback.clearIdToken();
		if (idToken == null || idToken.isBlank()) {
			throw new FailedLoginException("OIDC ID token required");
		}

		String expectedNonce = challengeStore.consume(oidcCallback.getLoginChallenge());
		if (expectedNonce == null) {
			throw new FailedLoginException("Authentication failed");
		}

		JWTClaimsSet claims;
		try {
			OidcIdTokenValidator validator = new OidcIdTokenValidator(config.getIssuer(),
				config.getAudience(), allowedSigningAlgs, config.getClockSkewSeconds(),
				Integer.valueOf(config.getMaxTokenAgeSeconds()), expectedNonce, jwkSource);
			claims = validator.validate(idToken);
		}
		catch (OidcIdTokenException e) {
			log.warn("OIDC ID token rejected ({})", e.getMessage());
			throw new FailedLoginException("Authentication failed");
		}

		return usernameMapper.map(claims);
	}

	private ResolvedEndpoints resolveEndpoints() {
		if (discoveryClient == null) {
			return new ResolvedEndpoints(deviceAuthorizationEndpoint, tokenEndpoint);
		}
		try {
			ProviderMetadata metadata = discoveryClient.getMetadata(config.getIssuer());
			OidcDiscoveryClient.validateDeviceCodeSupport(metadata, config.getAllowedSigningAlgs());
			applyEndpoints(metadata);
			return new ResolvedEndpoints(deviceAuthorizationEndpoint, tokenEndpoint);
		}
		catch (IOException e) {
			throw new RuntimeException("OIDC discovery failed", e);
		}
	}

	private void applyEndpoints(ProviderMetadata metadata) {
		this.deviceAuthorizationEndpoint =
			firstNonBlank(config.getDeviceAuthorizationEndpoint(),
				metadata.deviceAuthorizationEndpoint);
		this.tokenEndpoint = firstNonBlank(config.getTokenEndpoint(), metadata.tokenEndpoint);
	}

	private static JWKSource<SecurityContext> fileJwkSource(File jwksFile) throws IOException {
		try {
			return OidcIdTokenValidator.createFileJwkSource(jwksFile);
		}
		catch (ParseException e) {
			throw new IOException("Failed to parse jwksFile", e);
		}
	}

	static void validateJwksFileKeys(File jwksFile, Collection<String> allowedSigningAlgs)
			throws IOException {
		JWKSet jwkSet;
		try {
			jwkSet = JWKSet.load(jwksFile);
		}
		catch (IOException e) {
			throw e;
		}
		catch (ParseException e) {
			throw new IOException("Failed to parse jwksFile", e);
		}
		for (JWK jwk : jwkSet.getKeys()) {
			if (jwk.getKeyUse() != null && !KeyUse.SIGNATURE.equals(jwk.getKeyUse())) {
				continue;
			}
			if (keySupportsAllowedAlg(jwk, allowedSigningAlgs)) {
				return;
			}
		}
		throw new IllegalArgumentException(
			"jwksFile does not contain a key usable with allowedSigningAlgs");
	}

	private static boolean keySupportsAllowedAlg(JWK jwk, Collection<String> allowedSigningAlgs) {
		if (jwk.getAlgorithm() != null) {
			return containsIgnoreCase(allowedSigningAlgs, jwk.getAlgorithm().getName());
		}
		if (jwk instanceof RSAKey) {
			return containsIgnoreCase(allowedSigningAlgs, "RS256");
		}
		if (jwk instanceof ECKey) {
			Curve curve = ((ECKey) jwk).getCurve();
			return Curve.P_256.equals(curve) && containsIgnoreCase(allowedSigningAlgs, "ES256");
		}
		return false;
	}

	private static boolean containsIgnoreCase(Collection<String> values, String expected) {
		for (String value : values) {
			if (expected.equalsIgnoreCase(value)) {
				return true;
			}
		}
		return false;
	}

	private static String firstNonBlank(String preferred, String fallback) {
		if (preferred != null && !preferred.isBlank()) {
			return preferred;
		}
		return fallback;
	}

	private static final class ResolvedEndpoints {
		private final String deviceAuthorizationEndpoint;
		private final String tokenEndpoint;

		private ResolvedEndpoints(String deviceAuthorizationEndpoint, String tokenEndpoint) {
			this.deviceAuthorizationEndpoint = deviceAuthorizationEndpoint;
			this.tokenEndpoint = tokenEndpoint;
		}
	}
}
