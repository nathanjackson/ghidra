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

import static org.junit.Assert.*;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.Date;

import org.junit.Before;
import org.junit.Test;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;

import ghidra.server.security.oidc.OidcIdTokenValidator.OidcIdTokenException;

public class OidcIdTokenValidatorTest {

	private static final String ISSUER = "https://issuer.example.test";
	private static final String AUDIENCE = "ghidra-client";
	private static final String SUBJECT = "user-1";
	private static final String KID = "test-rsa";

	private RSAKey rsaKey;
	private OidcIdTokenValidator validator;

	@Before
	public void setUp() throws Exception {
		rsaKey = new RSAKeyGenerator(2048).keyID(KID)
				.keyUse(KeyUse.SIGNATURE)
				.algorithm(JWSAlgorithm.RS256)
				.generate();
		validator = validatorWithNonce(null);
	}

	@Test
	public void testRs256Success() throws Exception {
		JWTClaimsSet claims = validator.validate(sign(validClaims().build()));
		assertEquals(SUBJECT, claims.getSubject());
		assertEquals(ISSUER, claims.getIssuer());
		assertTrue(claims.getAudience().contains(AUDIENCE));
	}

	@Test
	public void testAlgNoneRejected() throws Exception {
		PlainJWT plain = new PlainJWT(validClaims().build());
		assertRejected(plain.serialize());
	}

	@Test
	public void testExpiredRejected() throws Exception {
		Date now = new Date();
		JWTClaimsSet.Builder claims = validClaims(new Date(now.getTime() - 120_000L),
			new Date(now.getTime() - 60_000L));
		assertRejected(sign(claims.build()));
	}

	@Test
	public void testWrongAudienceRejected() throws Exception {
		JWTClaimsSet claims = validClaims().audience("other-client").build();
		assertRejected(sign(claims));
	}

	@Test
	public void testJweRejected() throws Exception {
		EncryptedJWT jwe = new EncryptedJWT(
			new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM).build(),
			validClaims().build());
		jwe.encrypt(new RSAEncrypter(rsaKey.toPublicJWK()));
		assertRejected(jwe.serialize());
	}

	@Test
	public void testHs256ConfusionRejected() throws Exception {
		byte[] hmacKey = new byte[32];
		new SecureRandom().nextBytes(hmacKey);
		SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.HS256).build(),
			validClaims().build());
		jwt.sign(new MACSigner(hmacKey));
		assertRejected(jwt.serialize());
	}

	@Test
	public void testHs256UsingRsaPublicKeyRejected() throws Exception {
		byte[] hmacKey = rsaKey.toPublicJWK().toJSONString().getBytes(StandardCharsets.UTF_8);
		if (hmacKey.length < 32) {
			fail("HMAC key material too short for HS256");
		}
		SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.HS256).build(),
			validClaims().build());
		jwt.sign(new MACSigner(hmacKey));
		assertRejected(jwt.serialize());
	}

	@Test
	public void testMissingSubRejected() throws Exception {
		JWTClaimsSet claims = validClaims().subject(null).build();
		assertRejected(sign(claims));
	}

	@Test
	public void testNoncePresentAndWrongRejected() throws Exception {
		OidcIdTokenValidator nonceValidator = validatorWithNonce("expected-nonce");
		JWTClaimsSet claims = validClaims().claim("nonce", "wrong-nonce").build();
		assertRejected(nonceValidator, sign(claims));
	}

	@Test
	public void testNonceAbsentAccepted() throws Exception {
		OidcIdTokenValidator nonceValidator = validatorWithNonce("expected-nonce");
		JWTClaimsSet claims = nonceValidator.validate(sign(validClaims().build()));
		assertEquals(SUBJECT, claims.getSubject());
		assertNull(claims.getStringClaim("nonce"));
	}

	@Test
	public void testNoncePresentAndMatchingAccepted() throws Exception {
		OidcIdTokenValidator nonceValidator = validatorWithNonce("expected-nonce");
		JWTClaimsSet claims =
			nonceValidator.validate(sign(validClaims().claim("nonce", "expected-nonce").build()));
		assertEquals("expected-nonce", claims.getStringClaim("nonce"));
	}

	@Test
	public void testTokenUseAccessRejected() throws Exception {
		JWTClaimsSet claims = validClaims().claim("token_use", "access").build();
		assertRejected(sign(claims));
	}

	@Test
	public void testTypAtJwtRejected() throws Exception {
		assertRejected(sign(validClaims().build(), new JOSEObjectType("at+jwt")));
	}

	@Test
	public void testCritHeaderRejected() throws Exception {
		JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(KID)
				.criticalParams(Collections.singleton("bork"))
				.customParam("bork", Boolean.TRUE)
				.build();
		SignedJWT jwt = new SignedJWT(header, validClaims().build());
		jwt.sign(new RSASSASigner(rsaKey));
		assertRejected(jwt.serialize());
	}

	@Test
	public void testMaxTokenAgeRejected() throws Exception {
		OidcIdTokenValidator ageValidator = new OidcIdTokenValidator(ISSUER, AUDIENCE,
			null, 60, Integer.valueOf(30), null,
			OidcIdTokenValidator.createJwkSetSource(new JWKSet(rsaKey.toPublicJWK())));
		Date now = new Date();
		JWTClaimsSet claims = validClaims(new Date(now.getTime() - 120_000L),
			new Date(now.getTime() + 300_000L)).build();
		assertRejected(ageValidator, sign(claims));
	}

	private OidcIdTokenValidator validatorWithNonce(String expectedNonce) {
		return new OidcIdTokenValidator(ISSUER, AUDIENCE, null,
			OidcIdTokenValidator.DEFAULT_CLOCK_SKEW_SECONDS, null, expectedNonce,
			OidcIdTokenValidator.createJwkSetSource(new JWKSet(rsaKey.toPublicJWK())));
	}

	private JWTClaimsSet.Builder validClaims() {
		Date now = new Date();
		return validClaims(now, new Date(now.getTime() + 300_000L));
	}

	private JWTClaimsSet.Builder validClaims(Date iat, Date exp) {
		return new JWTClaimsSet.Builder().issuer(ISSUER)
				.audience(AUDIENCE)
				.subject(SUBJECT)
				.issueTime(iat)
				.expirationTime(exp);
	}

	private String sign(JWTClaimsSet claims) throws Exception {
		return sign(claims, JOSEObjectType.JWT);
	}

	private String sign(JWTClaimsSet claims, JOSEObjectType typ) throws Exception {
		JWSHeader.Builder header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(KID);
		if (typ != null) {
			header.type(typ);
		}
		SignedJWT jwt = new SignedJWT(header.build(), claims);
		jwt.sign(new RSASSASigner(rsaKey));
		return jwt.serialize();
	}

	private void assertRejected(String compact) {
		assertRejected(validator, compact);
	}

	private static void assertRejected(OidcIdTokenValidator idTokenValidator, String compact) {
		try {
			idTokenValidator.validate(compact);
			fail("Expected ID token to be rejected");
		}
		catch (OidcIdTokenException e) {
			assertNotNull(e.getMessage());
			assertFalse(compact != null && e.getMessage() != null &&
				compact.length() > 20 && e.getMessage().contains(compact));
		}
	}
}
