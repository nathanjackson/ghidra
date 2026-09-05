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

public class OidcAuthenticationCallbackTest extends AbstractGenericTest {

	private static final String ISSUER = "https://idp.example.com";
	private static final String CLIENT_ID = "ghidra-client";
	private static final String DEVICE_ENDPOINT = "https://idp.example.com/device";
	private static final String TOKEN_ENDPOINT = "https://idp.example.com/token";
	private static final String SCOPES = "openid profile";
	private static final String NONCE = "secret-nonce-xyz";
	private static final String LOGIN_CHALLENGE = "secret-challenge-xyz";
	private static final int LOGIN_TIMEOUT_SECONDS = 120;
	private static final String DISPLAY_NAME = "Example IdP";
	private static final String ID_TOKEN = "secret.id.token.xyz";

	public OidcAuthenticationCallbackTest() {
		super();
	}

	@Test
	public void testSerializationRoundTrip() throws Exception {
		OidcAuthenticationCallback original = newCallback();
		original.setIdToken(ID_TOKEN);

		OidcAuthenticationCallback copy = roundTrip(original);

		assertEquals(ISSUER, copy.getIssuer());
		assertEquals(CLIENT_ID, copy.getClientId());
		assertEquals(DEVICE_ENDPOINT, copy.getDeviceAuthorizationEndpoint());
		assertEquals(TOKEN_ENDPOINT, copy.getTokenEndpoint());
		assertEquals(SCOPES, copy.getScopes());
		assertEquals(NONCE, copy.getNonce());
		assertEquals(LOGIN_CHALLENGE, copy.getLoginChallenge());
		assertEquals(LOGIN_TIMEOUT_SECONDS, copy.getLoginTimeoutSeconds());
		assertEquals(DISPLAY_NAME, copy.getDisplayName());
		assertEquals(ID_TOKEN, copy.getIdToken());
	}

	@Test
	public void testSerializationRoundTripWithoutIdToken() throws Exception {
		OidcAuthenticationCallback copy = roundTrip(newCallback());
		assertNull(copy.getIdToken());
	}

	@Test
	public void testClearIdToken() {
		OidcAuthenticationCallback callback = newCallback();
		callback.setIdToken(ID_TOKEN);
		assertEquals(ID_TOKEN, callback.getIdToken());

		callback.clearIdToken();
		assertNull(callback.getIdToken());
	}

	@Test
	public void testToStringOmitsSecrets() {
		OidcAuthenticationCallback callback = newCallback();
		callback.setIdToken(ID_TOKEN);

		String text = callback.toString();
		assertTrue(text.contains(ISSUER));
		assertTrue(text.contains(CLIENT_ID));
		assertTrue(text.contains(DEVICE_ENDPOINT));
		assertTrue(text.contains(TOKEN_ENDPOINT));
		assertTrue(text.contains(SCOPES));
		assertTrue(text.contains(DISPLAY_NAME));
		assertFalse(text.contains(NONCE));
		assertFalse(text.contains(LOGIN_CHALLENGE));
		assertFalse(text.contains(ID_TOKEN));
	}

	private static OidcAuthenticationCallback newCallback() {
		return new OidcAuthenticationCallback(ISSUER, CLIENT_ID, DEVICE_ENDPOINT, TOKEN_ENDPOINT,
			SCOPES, NONCE, LOGIN_CHALLENGE, LOGIN_TIMEOUT_SECONDS, DISPLAY_NAME);
	}

	@SuppressWarnings("unchecked")
	private static <T> T roundTrip(T value) throws Exception {
		ByteArrayOutputStream bytes = new ByteArrayOutputStream();
		try (ObjectOutputStream out = new ObjectOutputStream(bytes)) {
			out.writeObject(value);
		}
		try (ObjectInputStream in =
			new ObjectInputStream(new ByteArrayInputStream(bytes.toByteArray()))) {
			return (T) in.readObject();
		}
	}

}
