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
package ghidra.server.security.fido;

import static org.junit.Assert.*;

import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.server.security.fido.FidoAssertionVerifier.Enrollment;
import ghidra.server.security.fido.FidoAssertionVerifier.VerificationException;

public class FidoAssertionVerifierTest extends AbstractGenericTest {

	private static final String RP_ID = "localhost";
	private static final String ORIGIN = "https://localhost";
	private static final byte[] CHALLENGE = FidoWebAuthnFixtures.bytes(1, 2, 3, 4, 5, 6, 7, 8, 9,
		10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32);

	private FidoAssertionVerifier verifier;
	private KeyPair es256;
	private byte[] cose;

	public FidoAssertionVerifierTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		verifier = new FidoAssertionVerifier(RP_ID);
		es256 = FidoWebAuthnFixtures.es256();
		cose = FidoWebAuthnFixtures.coseEs256((ECPublicKey) es256.getPublic());
	}

	@Test
	public void testAssertionSuccess() throws Exception {
		byte[] authData = FidoWebAuthnFixtures.authenticatorData(RP_ID,
			FidoAssertionVerifier.FLAG_UP | FidoAssertionVerifier.FLAG_UV, 3);
		byte[] clientData =
			FidoWebAuthnFixtures.clientDataJSON("webauthn.get", CHALLENGE, ORIGIN);
		byte[] signature =
			FidoWebAuthnFixtures.signEs256(es256.getPrivate(), authData, clientData);

		long count = verifier.verifyAssertion(CHALLENGE, authData, clientData, signature, cose, 2);
		assertEquals(3L, count);
	}

	@Test
	public void testAssertionAllowsBothZeroSignCount() throws Exception {
		byte[] authData = FidoWebAuthnFixtures.authenticatorData(RP_ID,
			FidoAssertionVerifier.FLAG_UP | FidoAssertionVerifier.FLAG_UV, 0);
		byte[] clientData =
			FidoWebAuthnFixtures.clientDataJSON("webauthn.get", CHALLENGE, ORIGIN);
		byte[] signature =
			FidoWebAuthnFixtures.signEs256(es256.getPrivate(), authData, clientData);

		assertEquals(0L,
			verifier.verifyAssertion(CHALLENGE, authData, clientData, signature, cose, 0));
	}

	@Test
	public void testAssertionAllowsLoopbackHttpOrigin() throws Exception {
		byte[] authData = FidoWebAuthnFixtures.authenticatorData(RP_ID,
			FidoAssertionVerifier.FLAG_UP | FidoAssertionVerifier.FLAG_UV, 1);
		byte[] clientData =
			FidoWebAuthnFixtures.clientDataJSON("webauthn.get", CHALLENGE, "http://localhost");
		byte[] signature =
			FidoWebAuthnFixtures.signEs256(es256.getPrivate(), authData, clientData);

		assertEquals(1L,
			verifier.verifyAssertion(CHALLENGE, authData, clientData, signature, cose, 0));
	}

	@Test
	public void testAssertionWrongChallenge() throws Exception {
		byte[] authData = FidoWebAuthnFixtures.authenticatorData(RP_ID,
			FidoAssertionVerifier.FLAG_UP | FidoAssertionVerifier.FLAG_UV, 1);
		byte[] other = CHALLENGE.clone();
		other[0] ^= 1;
		byte[] clientData = FidoWebAuthnFixtures.clientDataJSON("webauthn.get", other, ORIGIN);
		byte[] signature =
			FidoWebAuthnFixtures.signEs256(es256.getPrivate(), authData, clientData);

		try {
			verifier.verifyAssertion(CHALLENGE, authData, clientData, signature, cose, 0);
			fail("expected VerificationException");
		}
		catch (VerificationException e) {
			assertTrue(e.getMessage().contains("challenge"));
		}
	}

	@Test
	public void testAssertionWrongRpId() throws Exception {
		byte[] authData = FidoWebAuthnFixtures.authenticatorData("evil.example",
			FidoAssertionVerifier.FLAG_UP | FidoAssertionVerifier.FLAG_UV, 1);
		byte[] clientData =
			FidoWebAuthnFixtures.clientDataJSON("webauthn.get", CHALLENGE, ORIGIN);
		byte[] signature =
			FidoWebAuthnFixtures.signEs256(es256.getPrivate(), authData, clientData);

		try {
			verifier.verifyAssertion(CHALLENGE, authData, clientData, signature, cose, 0);
			fail("expected VerificationException");
		}
		catch (VerificationException e) {
			assertTrue(e.getMessage().contains("rpIdHash"));
		}
	}

	@Test
	public void testAssertionWrongOrigin() throws Exception {
		FidoAssertionVerifier prod = new FidoAssertionVerifier("ghidra.example.org");
		byte[] authData = FidoWebAuthnFixtures.authenticatorData("ghidra.example.org",
			FidoAssertionVerifier.FLAG_UP | FidoAssertionVerifier.FLAG_UV, 1);
		byte[] clientData =
			FidoWebAuthnFixtures.clientDataJSON("webauthn.get", CHALLENGE, "http://localhost");
		byte[] signature =
			FidoWebAuthnFixtures.signEs256(es256.getPrivate(), authData, clientData);
		byte[] prodCose = FidoWebAuthnFixtures.coseEs256((ECPublicKey) es256.getPublic());

		try {
			prod.verifyAssertion(CHALLENGE, authData, clientData, signature, prodCose, 0);
			fail("expected VerificationException");
		}
		catch (VerificationException e) {
			assertTrue(e.getMessage().contains("origin"));
		}
	}

	@Test
	public void testAssertionUvMissing() throws Exception {
		byte[] authData = FidoWebAuthnFixtures.authenticatorData(RP_ID,
			FidoAssertionVerifier.FLAG_UP, 1);
		byte[] clientData =
			FidoWebAuthnFixtures.clientDataJSON("webauthn.get", CHALLENGE, ORIGIN);
		byte[] signature =
			FidoWebAuthnFixtures.signEs256(es256.getPrivate(), authData, clientData);

		try {
			verifier.verifyAssertion(CHALLENGE, authData, clientData, signature, cose, 0);
			fail("expected VerificationException");
		}
		catch (VerificationException e) {
			assertTrue(e.getMessage().contains("user verification"));
		}
	}

	@Test
	public void testAssertionSignCountEqualRejected() throws Exception {
		byte[] authData = FidoWebAuthnFixtures.authenticatorData(RP_ID,
			FidoAssertionVerifier.FLAG_UP | FidoAssertionVerifier.FLAG_UV, 5);
		byte[] clientData =
			FidoWebAuthnFixtures.clientDataJSON("webauthn.get", CHALLENGE, ORIGIN);
		byte[] signature =
			FidoWebAuthnFixtures.signEs256(es256.getPrivate(), authData, clientData);

		try {
			verifier.verifyAssertion(CHALLENGE, authData, clientData, signature, cose, 5);
			fail("expected VerificationException");
		}
		catch (VerificationException e) {
			assertTrue(e.getMessage().contains("signCount"));
		}
	}

	@Test
	public void testAssertionSignCountDecrease() throws Exception {
		byte[] authData = FidoWebAuthnFixtures.authenticatorData(RP_ID,
			FidoAssertionVerifier.FLAG_UP | FidoAssertionVerifier.FLAG_UV, 4);
		byte[] clientData =
			FidoWebAuthnFixtures.clientDataJSON("webauthn.get", CHALLENGE, ORIGIN);
		byte[] signature =
			FidoWebAuthnFixtures.signEs256(es256.getPrivate(), authData, clientData);

		try {
			verifier.verifyAssertion(CHALLENGE, authData, clientData, signature, cose, 5);
			fail("expected VerificationException");
		}
		catch (VerificationException e) {
			assertTrue(e.getMessage().contains("signCount"));
		}
	}

	@Test
	public void testEnrollNoneAttestation() throws Exception {
		int flags = FidoAssertionVerifier.FLAG_UP | FidoAssertionVerifier.FLAG_UV |
			FidoAssertionVerifier.FLAG_AT;
		byte[] authData = FidoWebAuthnFixtures.authenticatorData(RP_ID, flags, 0,
			FidoWebAuthnFixtures.CRED_ID, cose);
		byte[] clientData =
			FidoWebAuthnFixtures.clientDataJSON("webauthn.create", CHALLENGE, ORIGIN);
		byte[] attestation = FidoWebAuthnFixtures.attestationNone(authData);

		Enrollment enrollment =
			verifier.verifyAttestation(CHALLENGE, authData, clientData, attestation);
		assertArrayEquals(FidoWebAuthnFixtures.CRED_ID, enrollment.getCredentialId());
		assertArrayEquals(cose, enrollment.getPublicKeyCose());
		assertEquals(0L, enrollment.getSignCount());
		assertArrayEquals(FidoWebAuthnFixtures.AAGUID, enrollment.getAaguid());
	}

	@Test
	public void testEnrollPackedRejected() throws Exception {
		expectAttestationReject(FidoWebAuthnFixtures.attestationFmt(enrollAuthData(), "packed"),
			"format");
	}

	@Test
	public void testCoseRsaKtyRejected() throws Exception {
		try {
			FidoAssertionVerifier.parseCosePublicKey(FidoWebAuthnFixtures.coseRsaKty());
			fail("expected VerificationException");
		}
		catch (VerificationException e) {
			assertTrue(e.getMessage().toLowerCase().contains("kty"));
		}
	}

	@Test
	public void testRpIdNormalizedToLowercase() {
		FidoAssertionVerifier mixed = new FidoAssertionVerifier("LocalHost");
		assertEquals("localhost", mixed.getRpId());
	}

	@Test
	public void testAssertionAuthenticatorDataTooLarge() throws Exception {
		byte[] huge = new byte[257];
		Arrays.fill(huge, (byte) 0);
		try {
			verifier.verifyAssertion(CHALLENGE, huge, new byte[] { '{', '}' }, new byte[] { 1 },
				cose, 0);
			fail("expected VerificationException");
		}
		catch (VerificationException e) {
			assertTrue(e.getMessage().contains("too large"));
		}
	}

	@Test
	public void testCoseAlgRequired() throws Exception {
		byte[] noAlg = FidoWebAuthnFixtures.coseEs256WithoutAlg((ECPublicKey) es256.getPublic());
		byte[] authData = FidoWebAuthnFixtures.authenticatorData(RP_ID,
			FidoAssertionVerifier.FLAG_UP | FidoAssertionVerifier.FLAG_UV, 1);
		byte[] clientData =
			FidoWebAuthnFixtures.clientDataJSON("webauthn.get", CHALLENGE, ORIGIN);
		byte[] signature =
			FidoWebAuthnFixtures.signEs256(es256.getPrivate(), authData, clientData);
		try {
			verifier.verifyAssertion(CHALLENGE, authData, clientData, signature, noAlg, 0);
			fail("expected VerificationException");
		}
		catch (VerificationException e) {
			assertTrue(e.getMessage().contains("alg"));
		}
	}

	@Test
	public void testClientDataJsonTooLarge() throws Exception {
		byte[] huge = new byte[5000];
		Arrays.fill(huge, (byte) '[');
		byte[] authData = FidoWebAuthnFixtures.authenticatorData(RP_ID,
			FidoAssertionVerifier.FLAG_UP | FidoAssertionVerifier.FLAG_UV, 1);
		try {
			verifier.verifyAssertion(CHALLENGE, authData, huge, new byte[] { 1 }, cose, 0);
			fail("expected VerificationException");
		}
		catch (VerificationException e) {
			assertTrue(e.getMessage().contains("too large") ||
				e.getMessage().contains("clientDataJSON"));
		}
	}

	@Test
	public void testClientDataJsonNonObject() throws Exception {
		byte[] authData = FidoWebAuthnFixtures.authenticatorData(RP_ID,
			FidoAssertionVerifier.FLAG_UP | FidoAssertionVerifier.FLAG_UV, 1);
		try {
			verifier.verifyAssertion(CHALLENGE, authData, "[]".getBytes(), new byte[] { 1 }, cose,
				0);
			fail("expected VerificationException");
		}
		catch (VerificationException e) {
			assertTrue(e.getMessage().contains("clientDataJSON"));
		}
	}

	@Test
	public void testEnrollUnknownFmt() throws Exception {
		expectAttestationReject(FidoWebAuthnFixtures.attestationFmt(enrollAuthData(), "tpm"),
			"format");
	}

	@Test
	public void testEnrollTrailingCborRejected() throws Exception {
		byte[] attestation = FidoWebAuthnFixtures.attestationNone(enrollAuthData());
		expectAttestationReject(FidoWebAuthnFixtures.concat(attestation, new byte[] { 0x00 }),
			"trailing");
	}

	@Test
	public void testEnrollCborTagRejected() throws Exception {
		byte[] attestation = FidoWebAuthnFixtures.attestationNone(enrollAuthData());
		byte[] tagged = new byte[attestation.length + 8];
		Arrays.fill(tagged, (byte) 0xC0);
		System.arraycopy(attestation, 0, tagged, 8, attestation.length);
		expectAttestationReject(tagged, "tag");
	}

	@Test
	public void testEnrollNoneRequiresEmptyAttStmt() throws Exception {
		expectAttestationReject(
			FidoWebAuthnFixtures.attestationNoneWithStmt(enrollAuthData(), false), "attStmt");
	}

	@Test
	public void testP1363ToDerHighBit() throws Exception {
		byte[] raw = new byte[64];
		Arrays.fill(raw, 0, 32, (byte) 0xFF);
		raw[32] = 0x01;
		byte[] der = FidoAssertionVerifier.p1363ToDer(raw);
		assertEquals(0x30, der[0] & 0xff);
		assertEquals(0x02, der[2] & 0xff);
		assertEquals(33, der[3] & 0xff); // leading 0x00 for high-bit r
		assertEquals(0, der[4]);
	}

	private byte[] enrollAuthData() {
		int flags = FidoAssertionVerifier.FLAG_UP | FidoAssertionVerifier.FLAG_UV |
			FidoAssertionVerifier.FLAG_AT;
		return FidoWebAuthnFixtures.authenticatorData(RP_ID, flags, 0,
			FidoWebAuthnFixtures.CRED_ID, cose);
	}

	private void expectAttestationReject(byte[] attestation, String messageFragment)
			throws Exception {
		byte[] clientData =
			FidoWebAuthnFixtures.clientDataJSON("webauthn.create", CHALLENGE, ORIGIN);
		try {
			verifier.verifyAttestation(CHALLENGE, enrollAuthData(), clientData, attestation);
			fail("expected VerificationException containing " + messageFragment);
		}
		catch (VerificationException e) {
			assertTrue(e.getMessage(),
				e.getMessage().toLowerCase().contains(messageFragment.toLowerCase()));
		}
	}
}
