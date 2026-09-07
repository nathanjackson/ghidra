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
package ghidra.framework.remote;

import static org.junit.Assert.*;

import java.io.*;

import org.junit.Test;

import generic.test.AbstractGenericTest;

public class FidoAuthenticationCallbackTest extends AbstractGenericTest {

	private static final String RP_ID = "ghidra.example.org";
	private static final String RP_NAME = "Example Ghidra Server";
	private static final byte[] CHALLENGE = bytes(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32);
	private static final byte[] CRED_ID_1 = bytes(0xAA, 0xBB, 0xCC);
	private static final byte[] CRED_ID_2 = bytes(0xDD, 0xEE);
	private static final byte[] AUTH_DATA = bytes(0x10, 0x11, 0x12);
	private static final byte[] CLIENT_DATA = bytes('{', '}', 0x01);
	private static final byte[] SIGNATURE = bytes(0x51, 0x52, 0x53, 0x54);
	private static final byte[] ATTESTATION = bytes(0xA3, 0x01, 0x02);
	private static final String ENROLL_TOKEN = "one-time-admin-code";

	public FidoAuthenticationCallbackTest() {
		super();
	}

	@Test
	public void testSerializationRoundTripAssertion() throws Exception {
		FidoAuthenticationCallback original = new FidoAuthenticationCallback(RP_ID, RP_NAME,
			CHALLENGE, new byte[][] { CRED_ID_1, CRED_ID_2 }, false, 60);
		original.setAssertion(CRED_ID_1, AUTH_DATA, CLIENT_DATA, SIGNATURE);
		original.setEnrollToken(ENROLL_TOKEN);

		FidoAuthenticationCallback copy = roundTrip(original);

		assertEquals(RP_ID, copy.getRpId());
		assertEquals(RP_NAME, copy.getRpName());
		assertArrayEquals(CHALLENGE, copy.getChallenge());
		assertFalse(copy.isEnroll());
		assertEquals(60, copy.getTimeoutSeconds());
		byte[][] allow = copy.getAllowCredentials();
		assertEquals(2, allow.length);
		assertArrayEquals(CRED_ID_1, allow[0]);
		assertArrayEquals(CRED_ID_2, allow[1]);
		assertArrayEquals(CRED_ID_1, copy.getCredentialId());
		assertArrayEquals(AUTH_DATA, copy.getAuthenticatorData());
		assertArrayEquals(CLIENT_DATA, copy.getClientDataJSON());
		assertArrayEquals(SIGNATURE, copy.getSignature());
		assertEquals(ENROLL_TOKEN, copy.getEnrollToken());
		assertNull(copy.getAttestationObject());
	}

	@Test
	public void testSerializationRoundTripEnroll() throws Exception {
		FidoAuthenticationCallback original =
			new FidoAuthenticationCallback(RP_ID, null, CHALLENGE, null, true, 90);
		original.setEnrollToken(ENROLL_TOKEN);
		original.setAssertion(CRED_ID_1, AUTH_DATA, CLIENT_DATA, SIGNATURE);
		original.setAttestationObject(ATTESTATION);

		FidoAuthenticationCallback copy = roundTrip(original);

		assertEquals(RP_ID, copy.getRpId());
		assertNull(copy.getRpName());
		assertArrayEquals(CHALLENGE, copy.getChallenge());
		assertTrue(copy.isEnroll());
		assertEquals(90, copy.getTimeoutSeconds());
		assertNull(copy.getAllowCredentials());
		assertEquals(ENROLL_TOKEN, copy.getEnrollToken());
		assertArrayEquals(CRED_ID_1, copy.getCredentialId());
		assertArrayEquals(AUTH_DATA, copy.getAuthenticatorData());
		assertArrayEquals(CLIENT_DATA, copy.getClientDataJSON());
		assertArrayEquals(SIGNATURE, copy.getSignature());
		assertArrayEquals(ATTESTATION, copy.getAttestationObject());
	}

	@Test
	public void testNullAndEmptyAllowCredentialsForEnroll() {
		FidoAuthenticationCallback withNull =
			new FidoAuthenticationCallback(RP_ID, RP_NAME, CHALLENGE, null, true, 60);
		assertTrue(withNull.isEnroll());
		assertNull(withNull.getAllowCredentials());

		FidoAuthenticationCallback withEmpty =
			new FidoAuthenticationCallback(RP_ID, RP_NAME, CHALLENGE, new byte[0][], true, 60);
		assertTrue(withEmpty.isEnroll());
		byte[][] empty = withEmpty.getAllowCredentials();
		assertNotNull(empty);
		assertEquals(0, empty.length);
	}

	@Test
	public void testToStringOmitsSecrets() {
		FidoAuthenticationCallback cb = new FidoAuthenticationCallback(RP_ID, RP_NAME, CHALLENGE,
			new byte[][] { CRED_ID_1, CRED_ID_2 }, false, 60);
		cb.setEnrollToken(ENROLL_TOKEN);
		cb.setAssertion(CRED_ID_1, AUTH_DATA, CLIENT_DATA, SIGNATURE);
		cb.setAttestationObject(ATTESTATION);

		String text = cb.toString();
		assertTrue(text.contains(RP_ID));
		assertTrue(text.contains(RP_NAME));
		assertTrue(text.contains("enroll=false"));
		assertTrue(text.contains("timeoutSeconds=60"));
		assertTrue(text.contains("allowCredentials=2"));

		assertFalse(text.contains("challenge"));
		assertFalse(text.contains(ENROLL_TOKEN));
		assertFalse(text.contains("one-time"));
		assertFalse(text.contains("authenticatorData"));
		assertFalse(text.contains("clientDataJSON"));
		assertFalse(text.contains("attestationObject"));
		assertFalse(text.contains("signature"));
		assertFalse(text.contains(new String(CHALLENGE)));
		assertFalse(text.contains(new String(SIGNATURE)));
		assertFalse(text.contains(new String(AUTH_DATA)));
		assertFalse(text.contains(new String(CLIENT_DATA)));
		assertFalse(text.contains(new String(ATTESTATION)));
	}

	@Test
	public void testClearEnrollTokenAndAssertionWipeSecrets() {
		FidoAuthenticationCallback cb = new FidoAuthenticationCallback(RP_ID, RP_NAME, CHALLENGE,
			new byte[][] { CRED_ID_1 }, false, 60);
		cb.setEnrollToken(ENROLL_TOKEN);
		cb.setAssertion(CRED_ID_1, AUTH_DATA, CLIENT_DATA, SIGNATURE);
		cb.setAttestationObject(ATTESTATION);

		cb.clearEnrollToken();
		assertNull(cb.getEnrollToken());

		cb.clearAssertion();
		assertNull(cb.getCredentialId());
		assertNull(cb.getAuthenticatorData());
		assertNull(cb.getClientDataJSON());
		assertNull(cb.getSignature());

		cb.clearAttestationObject();
		assertNull(cb.getAttestationObject());

		// Server-populated fields are left intact
		assertArrayEquals(CHALLENGE, cb.getChallenge());
		assertEquals(RP_ID, cb.getRpId());
	}

	@Test
	public void testDefensiveCopiesOnGet() {
		FidoAuthenticationCallback cb = new FidoAuthenticationCallback(RP_ID, RP_NAME, CHALLENGE,
			new byte[][] { CRED_ID_1, CRED_ID_2 }, false, 60);
		cb.setAssertion(CRED_ID_1, AUTH_DATA, CLIENT_DATA, SIGNATURE);
		cb.setAttestationObject(ATTESTATION);

		cb.getChallenge()[0] ^= 0xFF;
		assertEquals(CHALLENGE[0], cb.getChallenge()[0]);

		byte[][] allow = cb.getAllowCredentials();
		allow[0][0] ^= 0xFF;
		allow[0] = bytes(0x00);
		assertArrayEquals(CRED_ID_1, cb.getAllowCredentials()[0]);

		cb.getCredentialId()[0] ^= 0xFF;
		assertEquals(CRED_ID_1[0], cb.getCredentialId()[0]);

		cb.getAuthenticatorData()[0] ^= 0xFF;
		assertEquals(AUTH_DATA[0], cb.getAuthenticatorData()[0]);

		cb.getClientDataJSON()[0] ^= 0xFF;
		assertEquals(CLIENT_DATA[0], cb.getClientDataJSON()[0]);

		cb.getSignature()[0] ^= 0xFF;
		assertEquals(SIGNATURE[0], cb.getSignature()[0]);

		cb.getAttestationObject()[0] ^= 0xFF;
		assertEquals(ATTESTATION[0], cb.getAttestationObject()[0]);
	}

	@Test
	public void testDefensiveCopiesOnConstructAndSet() {
		byte[] challenge = CHALLENGE.clone();
		byte[] cred1 = CRED_ID_1.clone();
		byte[][] allow = new byte[][] { cred1 };
		FidoAuthenticationCallback cb =
			new FidoAuthenticationCallback(RP_ID, RP_NAME, challenge, allow, false, 60);

		challenge[0] ^= 0xFF;
		cred1[0] ^= 0xFF;
		allow[0] = bytes(0x00);
		assertArrayEquals(CHALLENGE, cb.getChallenge());
		assertArrayEquals(CRED_ID_1, cb.getAllowCredentials()[0]);

		byte[] credId = CRED_ID_1.clone();
		byte[] authData = AUTH_DATA.clone();
		byte[] clientData = CLIENT_DATA.clone();
		byte[] signature = SIGNATURE.clone();
		byte[] attestation = ATTESTATION.clone();
		cb.setAssertion(credId, authData, clientData, signature);
		cb.setAttestationObject(attestation);

		credId[0] ^= 0xFF;
		authData[0] ^= 0xFF;
		clientData[0] ^= 0xFF;
		signature[0] ^= 0xFF;
		attestation[0] ^= 0xFF;
		assertArrayEquals(CRED_ID_1, cb.getCredentialId());
		assertArrayEquals(AUTH_DATA, cb.getAuthenticatorData());
		assertArrayEquals(CLIENT_DATA, cb.getClientDataJSON());
		assertArrayEquals(SIGNATURE, cb.getSignature());
		assertArrayEquals(ATTESTATION, cb.getAttestationObject());
	}

	@SuppressWarnings("unchecked")
	private static <T> T roundTrip(T obj) throws Exception {
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		try (ObjectOutputStream oos = new ObjectOutputStream(bos)) {
			oos.writeObject(obj);
		}
		try (ObjectInputStream ois =
			new ObjectInputStream(new ByteArrayInputStream(bos.toByteArray()))) {
			return (T) ois.readObject();
		}
	}

}
