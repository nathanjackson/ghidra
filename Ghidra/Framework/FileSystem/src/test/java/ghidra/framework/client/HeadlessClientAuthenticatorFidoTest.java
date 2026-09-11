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
package ghidra.framework.client;

import static org.junit.Assert.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;

import org.junit.After;
import org.junit.Test;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import generic.test.AbstractGenericTest;
import ghidra.framework.client.fido.FidoAuthenticator;
import ghidra.framework.client.fido.FidoRpId;
import ghidra.framework.remote.FidoAuthenticationCallback;

public class HeadlessClientAuthenticatorFidoTest extends AbstractGenericTest {

	private static final String RP_ID = "ghidra.example.org";
	private static final byte[] CHALLENGE = bytes(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32);
	private static final byte[] CRED_ID = bytes(0xAA, 0xBB, 0xCC);
	private static final byte[] AUTH_DATA = bytes(0x10, 0x11, 0x12);
	private static final byte[] CLIENT_DATA = bytes('{', '}');
	private static final byte[] SIGNATURE = bytes(0x51, 0x52);
	private static final byte[] ATTESTATION = bytes(0xA3, 0x01);
	private static final String PIN = "s3cret-pin";

	@After
	public void tearDown() {
		ClientUtil.setClientAuthenticator(new PasswordClientAuthenticator("unused"));
	}

	@Test
	public void testHeadlessAssertUsesNameCallbackAndFakeHelper() throws Exception {
		AtomicReference<String> seen = new AtomicReference<>();
		HeadlessClientAuthenticator auth = newAuthenticator(seen, false, Map.of());
		NameCallback nameCb = new NameCallback("User ID:");
		nameCb.setName("alice");
		FidoAuthenticationCallback fido = newCallback();

		ByteArrayOutputStream err = new ByteArrayOutputStream();
		PrintStream oldErr = System.err;
		System.setErr(new PrintStream(err, true, StandardCharsets.UTF_8));
		try {
			assertTrue(auth.processFidoCallback(nameCb, fido, RP_ID));
		}
		finally {
			System.setErr(oldErr);
		}

		assertEquals("alice", nameCb.getName());
		assertArrayEquals(CRED_ID, fido.getCredentialId());
		assertArrayEquals(SIGNATURE, fido.getSignature());
		assertNull(fido.getAttestationObject());
		String errText = err.toString(StandardCharsets.UTF_8);
		assertTrue(errText.contains(HeadlessClientAuthenticator.FIDO_TOUCH_PROMPT));
		assertTrue(errText.contains(HeadlessClientAuthenticator.FIDO_RP_PROMPT_PREFIX + RP_ID));

		JsonObject req = JsonParser.parseString(seen.get()).getAsJsonObject();
		assertEquals("assert", req.get("op").getAsString());
		assertEquals("alice", req.get("userName").getAsString());
		assertFalse(req.has("pin"));
	}

	@Test
	public void testHeadlessEnrollAndPinFromEnv() throws Exception {
		AtomicReference<String> seen = new AtomicReference<>();
		Map<String, String> env = Map.of(HeadlessClientAuthenticator.FIDO_ENROLL_TOKEN_ENV,
			" one-time-admin-code ", HeadlessClientAuthenticator.FIDO_PIN_ENV, PIN);
		HeadlessClientAuthenticator auth = newAuthenticator(seen, true, env);
		NameCallback nameCb = new NameCallback("User ID:", "bob");
		FidoAuthenticationCallback fido = newCallback();

		assertTrue(auth.processFidoCallback(nameCb, fido, RP_ID));

		assertEquals("bob", nameCb.getName());
		assertArrayEquals(ATTESTATION, fido.getAttestationObject());
		assertEquals("one-time-admin-code", fido.getEnrollToken());

		JsonObject req = JsonParser.parseString(seen.get()).getAsJsonObject();
		assertEquals("create", req.get("op").getAsString());
		assertEquals(PIN, req.get("pin").getAsString());
	}

	@Test
	public void testHeadlessWipesPinAfterUse() throws Exception {
		AtomicReference<char[]> pinSeen = new AtomicReference<>();
		FidoAuthenticator authenticator = new FidoAuthenticator((json, timeoutMs) -> {
			JsonObject req = JsonParser.parseString(json).getAsJsonObject();
			assertEquals(PIN, req.get("pin").getAsString());
			return successJson(false);
		}) {
			@Override
			public void complete(FidoAuthenticationCallback fidoCb, String userName,
					String enrollToken, byte[][] allowCredentials, char[] pin, String connectedHost)
					throws IOException {
				pinSeen.set(pin);
				super.complete(fidoCb, userName, enrollToken, allowCredentials, pin, connectedHost);
			}
		};
		Map<String, String> env = Map.of(HeadlessClientAuthenticator.FIDO_PIN_ENV, PIN);
		HeadlessClientAuthenticator auth = new HeadlessClientAuthenticator(authenticator, env::get);
		assertTrue(auth.processFidoCallback(new NameCallback("User ID:", "alice"), newCallback(),
			RP_ID));

		char[] pin = pinSeen.get();
		assertNotNull(pin);
		assertEquals(PIN.length(), pin.length);
		for (char c : pin) {
			assertEquals('\0', c);
		}
	}

	@Test
	public void testHeadlessUsesClientUtilUserNameWhenNameCallbackBlank() throws Exception {
		AtomicReference<String> seen = new AtomicReference<>();
		HeadlessClientAuthenticator auth = newAuthenticator(seen, false, Map.of());
		FidoAuthenticationCallback fido = newCallback();
		assertTrue(auth.processFidoCallback(null, fido, RP_ID));

		JsonObject req = JsonParser.parseString(seen.get()).getAsJsonObject();
		assertEquals(ClientUtil.getUserName(), req.get("userName").getAsString());
		assertArrayEquals(CRED_ID, fido.getCredentialId());
	}

	@Test
	public void testHeadlessHelperFailureIsIOExceptionWithoutPin() throws Exception {
		FidoAuthenticator authenticator = new FidoAuthenticator((json, timeoutMs) -> {
			throw new IOException("touch timeout " + PIN);
		});
		Map<String, String> env = Map.of(HeadlessClientAuthenticator.FIDO_PIN_ENV, PIN);
		HeadlessClientAuthenticator auth = new HeadlessClientAuthenticator(authenticator, env::get);
		try {
			auth.processFidoCallback(new NameCallback("User ID:", "alice"), newCallback(),
				RP_ID);
			fail("expected IOException");
		}
		catch (IOException e) {
			assertFalse(e.getMessage().contains(PIN));
		}
	}

	@Test
	public void testHeadlessMismatchedHostFailsBeforeHelper() throws Exception {
		AtomicReference<String> seen = new AtomicReference<>();
		HeadlessClientAuthenticator auth = newAuthenticator(seen, false, Map.of());
		try {
			auth.processFidoCallback(new NameCallback("User ID:", "alice"), newCallback(),
				"evil.com");
			fail("expected IOException");
		}
		catch (IOException e) {
			assertEquals(FidoRpId.MISMATCH_MESSAGE, e.getMessage());
		}
		assertNull(seen.get());
	}

	@Test
	public void testClientUtilHeadlessUsesAllowLookup() throws Exception {
		AtomicReference<String> seen = new AtomicReference<>();
		HeadlessClientAuthenticator auth = newAuthenticator(seen, false, Map.of());
		ClientUtil.setClientAuthenticator(auth);
		NameCallback nameCb = new NameCallback("User ID:");
		nameCb.setName("alice");
		FidoAuthenticationCallback fido = newCallback();
		ClientFidoAuthenticatorTest.FakeHandle handle =
			new ClientFidoAuthenticatorTest.FakeHandle(new byte[][] { CRED_ID });

		assertTrue(ClientUtil.processFidoCallback(new Callback[] { nameCb, fido },
			RP_ID, "alice", handle, null));

		JsonObject req = JsonParser.parseString(seen.get()).getAsJsonObject();
		assertEquals(1, req.getAsJsonArray("allowCredentials").size());
		assertEquals(b64url(CRED_ID),
			req.getAsJsonArray("allowCredentials").get(0).getAsString());
	}

	private static HeadlessClientAuthenticator newAuthenticator(AtomicReference<String> seen,
			boolean create, Map<String, String> env) {
		FidoAuthenticator authenticator = new FidoAuthenticator((json, timeoutMs) -> {
			seen.set(json);
			return successJson(create);
		});
		return new HeadlessClientAuthenticator(authenticator, env::get);
	}

	private static FidoAuthenticationCallback newCallback() {
		return new FidoAuthenticationCallback(RP_ID, "Example", CHALLENGE, null, false, 60);
	}

	private static String successJson(boolean create) {
		JsonObject obj = new JsonObject();
		obj.addProperty("credentialId", b64url(CRED_ID));
		obj.addProperty("authenticatorData", b64url(AUTH_DATA));
		obj.addProperty("clientDataJSON", b64url(CLIENT_DATA));
		obj.addProperty("signature", b64url(SIGNATURE));
		if (create) {
			obj.addProperty("attestationObject", b64url(ATTESTATION));
		}
		return obj.toString();
	}

	private static String b64url(byte[] data) {
		return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
	}
}
