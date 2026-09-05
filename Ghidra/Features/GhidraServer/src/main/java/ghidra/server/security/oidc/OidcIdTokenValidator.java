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
import java.net.URL;
import java.text.ParseException;
import java.util.*;

import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jwt.util.DateUtils;

/**
 * Fail-closed validator for compact JWS OpenID Connect ID tokens.
 * <p>
 * Issuer and audience are taken from configuration, never from the token, when
 * deciding what to trust. Token contents are never logged.
 */
public final class OidcIdTokenValidator {

	public static final int DEFAULT_CLOCK_SKEW_SECONDS = 60;

	public static final Set<String> DEFAULT_ALLOWED_SIGNING_ALGS =
		Collections.unmodifiableSet(new LinkedHashSet<>(Arrays.asList("RS256", "ES256")));

	static final int JWKS_HTTP_TIMEOUT_MS = 10_000;
	static final long JWKS_CACHE_TTL_MS = 15 * 60_000L;

	private static final String TOKEN_USE_CLAIM = "token_use";
	private static final String NONCE_CLAIM = "nonce";
	private static final String ACCESS_TOKEN_USE = "access";

	private final String expectedNonce;
	private final int clockSkewSeconds;
	private final Integer maxTokenAgeSeconds;
	private final Set<JWSAlgorithm> allowedSigningAlgs;
	private final ConfigurableJWTProcessor<SecurityContext> jwtProcessor;

	/**
	 * @param issuer trusted issuer (from config, not from the token)
	 * @param audience accepted audience; defaults to the OIDC client ID
	 * @param allowedSigningAlgs JWS alg allowlist, or {@code null} for
	 *            {@link #DEFAULT_ALLOWED_SIGNING_ALGS}
	 * @param clockSkewSeconds clock skew for exp / nbf / iat; default
	 *            {@link #DEFAULT_CLOCK_SKEW_SECONDS}
	 * @param maxTokenAgeSeconds maximum age of {@code iat}, or {@code null}/non-positive
	 *            to disable
	 * @param expectedNonce required only when the token contains a nonce claim;
	 *            {@code null} if none
	 * @param jwkSource JWKS (URL, file, or in-memory set)
	 */
	public OidcIdTokenValidator(String issuer, String audience,
			Collection<String> allowedSigningAlgs, int clockSkewSeconds,
			Integer maxTokenAgeSeconds, String expectedNonce, JWKSource<SecurityContext> jwkSource) {

		if (isBlank(issuer)) {
			throw new IllegalArgumentException("issuer is required");
		}
		if (isBlank(audience)) {
			throw new IllegalArgumentException("audience is required");
		}
		if (jwkSource == null) {
			throw new IllegalArgumentException("JWKS source is required");
		}
		if (clockSkewSeconds < 0) {
			throw new IllegalArgumentException("clockSkewSeconds must be >= 0");
		}

		this.expectedNonce = expectedNonce;
		this.clockSkewSeconds = clockSkewSeconds;
		this.maxTokenAgeSeconds =
			(maxTokenAgeSeconds == null || maxTokenAgeSeconds <= 0) ? null : maxTokenAgeSeconds;
		this.allowedSigningAlgs = parseAllowedAlgs(allowedSigningAlgs);
		this.jwtProcessor = createProcessor(issuer, audience, jwkSource);
	}

	public OidcIdTokenValidator(String issuer, String audience,
			JWKSource<SecurityContext> jwkSource) {
		this(issuer, audience, null, DEFAULT_CLOCK_SKEW_SECONDS, null, null, jwkSource);
	}

	/**
	 * Remote HTTPS JWKS with 10s HTTP timeouts, a 15-minute cache, and a
	 * single refetch when {@code kid} is unknown.
	 * <p>
	 * The returned source is {@link java.io.Closeable} and starts a
	 * refresh-ahead executor; callers that own it should close it.
	 */
	public static JWKSource<SecurityContext> createRemoteJwkSource(URL jwksUrl) {
		if (jwksUrl == null) {
			throw new IllegalArgumentException("JWKS URL is required");
		}
		if (!"https".equalsIgnoreCase(jwksUrl.getProtocol())) {
			throw new IllegalArgumentException("JWKS URL must be https");
		}
		DefaultResourceRetriever retriever = new DefaultResourceRetriever(JWKS_HTTP_TIMEOUT_MS,
			JWKS_HTTP_TIMEOUT_MS, JWKSourceBuilder.DEFAULT_HTTP_SIZE_LIMIT);
		return JWKSourceBuilder.create(jwksUrl, retriever)
				.retrying(true)
				.cache(JWKS_CACHE_TTL_MS, JWKSourceBuilder.DEFAULT_CACHE_REFRESH_TIMEOUT)
				.build();
	}

	public static JWKSource<SecurityContext> createFileJwkSource(File jwksFile)
			throws IOException, ParseException {
		if (jwksFile == null) {
			throw new IllegalArgumentException("JWKS file is required");
		}
		return createJwkSetSource(JWKSet.load(jwksFile));
	}

	public static JWKSource<SecurityContext> createJwkSetSource(JWKSet jwkSet) {
		if (jwkSet == null) {
			throw new IllegalArgumentException("JWK set is required");
		}
		return new ImmutableJWKSet<>(jwkSet);
	}

	/**
	 * Validates a compact JWS ID token. Does not log the token.
	 *
	 * @return verified claims
	 * @throws OidcIdTokenException if the token is rejected
	 */
	public JWTClaimsSet validate(String compactIdToken) throws OidcIdTokenException {
		if (isBlank(compactIdToken)) {
			throw new OidcIdTokenException("ID token is required");
		}

		String[] parts = compactIdToken.split("\\.", -1);
		if (parts.length != 3) {
			throw new OidcIdTokenException("Only compact JWS ID tokens are accepted");
		}

		JWT jwt;
		try {
			jwt = JWTParser.parse(compactIdToken);
		}
		catch (ParseException e) {
			throw new OidcIdTokenException("ID token is not a compact JWS", e);
		}
		if (jwt instanceof PlainJWT) {
			throw new OidcIdTokenException("ID token signing algorithm is not allowed");
		}
		if (!(jwt instanceof SignedJWT)) {
			throw new OidcIdTokenException("Only compact JWS ID tokens are accepted");
		}
		SignedJWT signedJwt = (SignedJWT) jwt;

		rejectDisallowedHeader(signedJwt.getHeader());

		JWTClaimsSet claims;
		try {
			claims = jwtProcessor.process(signedJwt, null);
		}
		catch (BadJOSEException | JOSEException e) {
			throw new OidcIdTokenException("ID token rejected", e);
		}

		rejectBlankSubject(claims);
		rejectStaleOrFutureIat(claims);
		rejectNonceIfPresent(claims);
		rejectAccessTokenUse(claims);
		return claims;
	}

	private ConfigurableJWTProcessor<SecurityContext> createProcessor(String issuer,
			String audience, JWKSource<SecurityContext> jwkSource) {

		DefaultJWTClaimsVerifier<SecurityContext> claimsVerifier = new DefaultJWTClaimsVerifier<>(
			audience,
			new JWTClaimsSet.Builder().issuer(issuer).build(),
			new HashSet<>(Arrays.asList(JWTClaimNames.ISSUER, JWTClaimNames.SUBJECT,
				JWTClaimNames.AUDIENCE, JWTClaimNames.EXPIRATION_TIME, JWTClaimNames.ISSUED_AT)));
		claimsVerifier.setMaxClockSkew(clockSkewSeconds);

		ConfigurableJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
		processor.setJWSKeySelector(new JWSVerificationKeySelector<>(allowedSigningAlgs, jwkSource));
		processor.setJWSTypeVerifier((type, context) -> {
			try {
				verifyTyp(type);
			}
			catch (OidcIdTokenException e) {
				throw new BadJOSEException(e.getMessage(), e);
			}
		});
		processor.setJWTClaimsSetVerifier(claimsVerifier);
		return processor;
	}

	private void rejectDisallowedHeader(JWSHeader header) throws OidcIdTokenException {
		JWSAlgorithm alg = header.getAlgorithm();
		if (alg == null || JWSAlgorithm.NONE.equals(alg) ||
			JWSAlgorithm.Family.HMAC_SHA.contains(alg)) {
			throw new OidcIdTokenException("ID token signing algorithm is not allowed");
		}
		if (!allowedSigningAlgs.contains(alg)) {
			throw new OidcIdTokenException("ID token signing algorithm is not allowed");
		}
		if (header.getCriticalParams() != null && !header.getCriticalParams().isEmpty()) {
			throw new OidcIdTokenException("ID token crit header is not allowed");
		}
		verifyTyp(header.getType());
	}

	private static void verifyTyp(JOSEObjectType type) throws OidcIdTokenException {
		if (type == null) {
			return;
		}
		String value = type.toString();
		if ("at+jwt".equalsIgnoreCase(value) || "application/at+jwt".equalsIgnoreCase(value)) {
			throw new OidcIdTokenException("Access token typ is not accepted as an ID token");
		}
		if (!"JWT".equalsIgnoreCase(value) && !"application/jwt".equalsIgnoreCase(value)) {
			throw new OidcIdTokenException("ID token typ is not allowed");
		}
	}

	private static void rejectBlankSubject(JWTClaimsSet claims) throws OidcIdTokenException {
		if (isBlank(claims.getSubject())) {
			throw new OidcIdTokenException("ID token missing sub claim");
		}
	}

	private void rejectStaleOrFutureIat(JWTClaimsSet claims) throws OidcIdTokenException {
		Date iat = claims.getIssueTime();
		Date now = new Date();
		if (iat == null) {
			throw new OidcIdTokenException("ID token missing iat claim");
		}
		if (!DateUtils.isBefore(iat, now, clockSkewSeconds)) {
			throw new OidcIdTokenException("ID token iat is in the future");
		}
		if (maxTokenAgeSeconds != null) {
			long maxAgeMillis = (maxTokenAgeSeconds.longValue() + clockSkewSeconds) * 1000L;
			if (now.getTime() - iat.getTime() > maxAgeMillis) {
				throw new OidcIdTokenException("ID token exceeds max age");
			}
		}
	}

	private void rejectNonceIfPresent(JWTClaimsSet claims) throws OidcIdTokenException {
		String nonce;
		try {
			nonce = claims.getStringClaim(NONCE_CLAIM);
		}
		catch (ParseException e) {
			throw new OidcIdTokenException("ID token nonce is invalid", e);
		}
		if (nonce == null) {
			return;
		}
		if (expectedNonce == null || !expectedNonce.equals(nonce)) {
			throw new OidcIdTokenException("ID token nonce mismatch");
		}
	}

	private static void rejectAccessTokenUse(JWTClaimsSet claims) throws OidcIdTokenException {
		String tokenUse;
		try {
			tokenUse = claims.getStringClaim(TOKEN_USE_CLAIM);
		}
		catch (ParseException e) {
			throw new OidcIdTokenException("ID token token_use is invalid", e);
		}
		if (tokenUse != null && ACCESS_TOKEN_USE.equalsIgnoreCase(tokenUse)) {
			throw new OidcIdTokenException("Access tokens are not accepted as ID tokens");
		}
	}

	private static Set<JWSAlgorithm> parseAllowedAlgs(Collection<String> allowedSigningAlgs) {
		Collection<String> names = allowedSigningAlgs == null || allowedSigningAlgs.isEmpty()
				? DEFAULT_ALLOWED_SIGNING_ALGS
				: allowedSigningAlgs;
		Set<JWSAlgorithm> algs = new LinkedHashSet<>();
		for (String name : names) {
			if (isBlank(name)) {
				throw new IllegalArgumentException("allowedSigningAlgs contains a blank alg");
			}
			JWSAlgorithm alg = JWSAlgorithm.parse(name);
			if (JWSAlgorithm.NONE.equals(alg) || JWSAlgorithm.Family.HMAC_SHA.contains(alg)) {
				throw new IllegalArgumentException("Signing algorithm not allowed: " + name);
			}
			algs.add(alg);
		}
		if (algs.isEmpty()) {
			throw new IllegalArgumentException("allowedSigningAlgs must not be empty");
		}
		return Collections.unmodifiableSet(algs);
	}

	private static boolean isBlank(String value) {
		return value == null || value.trim().isEmpty();
	}

	public static final class OidcIdTokenException extends Exception {
		public OidcIdTokenException(String message) {
			super(message);
		}

		public OidcIdTokenException(String message, Throwable cause) {
			super(message, cause);
		}
	}
}
