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
package ghidra.framework.client.fido;

import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.Test;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import generic.test.AbstractGenericTest;
import ghidra.framework.remote.FidoAuthenticationCallback;
import ghidra.util.NumericUtilities;

public class FidoAuthenticatorTest extends AbstractGenericTest {

	private static final String RP_ID = "ghidra.example.org";
	private static final String RP_NAME = "Example Ghidra Server";
	private static final byte[] CHALLENGE = bytes(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32);
	private static final byte[] CRED_ID = bytes(0xAA, 0xBB, 0xCC);
	private static final byte[] AUTH_DATA = bytes(0x10, 0x11, 0x12);
	private static final byte[] CLIENT_DATA = bytes('{', '}', 0x01);
	private static final byte[] SIGNATURE = bytes(0x51, 0x52, 0x53, 0x54);
	private static final byte[] ATTESTATION = bytes(0xA3, 0x01, 0x02);
	private static final String ENROLL_TOKEN = "one-time-admin-code";

	@Test
	public void testAssertRoundTripFillsCallback() throws Exception {
		AtomicReference<String> seen = new AtomicReference<>();
		FidoAuthenticator auth = new FidoAuthenticator((json, timeoutMs) -> {
			seen.set(json);
			return successJson(false).toString();
		});
		FidoAuthenticationCallback cb = newCallback(false);
		auth.complete(cb, "alice", null, new byte[][] { CRED_ID });

		assertArrayEquals(CRED_ID, cb.getCredentialId());
		assertArrayEquals(AUTH_DATA, cb.getAuthenticatorData());
		assertArrayEquals(CLIENT_DATA, cb.getClientDataJSON());
		assertArrayEquals(SIGNATURE, cb.getSignature());
		assertNull(cb.getAttestationObject());
		assertNull(cb.getEnrollToken());

		JsonObject req = JsonParser.parseString(seen.get()).getAsJsonObject();
		assertEquals("assert", req.get("op").getAsString());
		assertEquals(RP_ID, req.get("rpId").getAsString());
		assertEquals(RP_NAME, req.get("rpName").getAsString());
		assertEquals("https://" + RP_ID, req.get("origin").getAsString());
		assertEquals(FidoAuthenticator.encodeBase64Url(CHALLENGE),
			req.get("challenge").getAsString());
		assertEquals("alice", req.get("userName").getAsString());
		assertEquals(FidoAuthenticator.encodeBase64Url(FidoAuthenticator.userIdFor("alice")),
			req.get("userId").getAsString());
		assertFalse(req.get("residentKey").getAsBoolean());
		assertEquals("required", req.get("userVerification").getAsString());
		assertEquals("cross-platform", req.get("authenticatorAttachment").getAsString());
		JsonArray allow = req.getAsJsonArray("allowCredentials");
		assertEquals(1, allow.size());
		assertEquals(FidoAuthenticator.encodeBase64Url(CRED_ID), allow.get(0).getAsString());
		assertFalse(seen.get().contains(ENROLL_TOKEN));
	}

	@Test
	public void testCreateRoundTripSetsAttestationAndEnrollToken() throws Exception {
		AtomicReference<String> seen = new AtomicReference<>();
		FidoAuthenticator auth = new FidoAuthenticator((json, timeoutMs) -> {
			seen.set(json);
			return successJson(true).toString();
		});
		FidoAuthenticationCallback cb = newCallback(false);
		auth.complete(cb, "bob", ENROLL_TOKEN, new byte[0][]);

		assertArrayEquals(CRED_ID, cb.getCredentialId());
		assertArrayEquals(ATTESTATION, cb.getAttestationObject());
		assertEquals(ENROLL_TOKEN, cb.getEnrollToken());
		JsonObject req = JsonParser.parseString(seen.get()).getAsJsonObject();
		assertEquals("create", req.get("op").getAsString());
		assertEquals(0, req.getAsJsonArray("allowCredentials").size());
	}

	@Test
	public void testHelperErrorBecomesIOExceptionWithoutSecrets() throws Exception {
		FidoAuthenticator auth = new FidoAuthenticator((json, timeoutMs) -> {
			JsonObject obj = new JsonObject();
			obj.addProperty("error", "touch timeout");
			obj.addProperty("signature", FidoAuthenticator.encodeBase64Url(SIGNATURE));
			return obj.toString();
		});
		FidoAuthenticationCallback cb = newCallback(false);
		try {
			auth.complete(cb, "alice", null, new byte[][] { CRED_ID });
			fail("expected IOException");
		}
		catch (IOException e) {
			assertEquals("touch timeout", e.getMessage());
			assertFalse(e.getMessage().contains(ENROLL_TOKEN));
			assertFalse(e.getMessage().contains(Arrays.toString(CHALLENGE)));
			assertFalse(e.getMessage().contains(NumericUtilities.convertBytesToString(SIGNATURE)));
		}
		assertNull(cb.getCredentialId());
		assertNull(cb.getSignature());
	}

	@Test
	public void testLoopbackOriginUsesHttp() {
		assertEquals("http://localhost", FidoAuthenticator.originFor("localhost"));
		assertEquals("http://127.0.0.1", FidoAuthenticator.originFor("127.0.0.1"));
		assertEquals("http://[::1]", FidoAuthenticator.originFor("::1"));
		assertEquals("https://ghidra.example.org", FidoAuthenticator.originFor("ghidra.example.org"));
	}

	@Test
	public void testProcessHelperJsonRoundTrip() throws Exception {
		File script = File.createTempFile("ghidra-fido-fake", ".sh");
		script.deleteOnExit();
		String json = successJson(false).toString();
		String body = "#!/bin/sh\ncat >/dev/null\nprintf '%s\\n' '" + json + "'\n";
		Files.writeString(script.toPath(), body, StandardCharsets.UTF_8);
		if (!script.setExecutable(true)) {
			return;
		}

		FidoAuthenticator auth =
			new FidoAuthenticator(new FidoAuthenticator.ProcessFidoHelper(script));
		FidoAuthenticationCallback cb = newCallback(false);
		auth.complete(cb, "alice", null, new byte[][] { CRED_ID });
		assertArrayEquals(CRED_ID, cb.getCredentialId());
		assertArrayEquals(SIGNATURE, cb.getSignature());
	}

	@Test
	public void testProcessHelperStderrIsNotCopied() throws Exception {
		File script = File.createTempFile("ghidra-fido-err", ".sh");
		script.deleteOnExit();
		String body = "#!/bin/sh\ncat >/dev/null\n" +
			"echo 'secret-signature-bytes challenge=AAAA enroll=token' >&2\nexit 2\n";
		Files.writeString(script.toPath(), body, StandardCharsets.UTF_8);
		if (!script.setExecutable(true)) {
			return;
		}

		FidoAuthenticator auth =
			new FidoAuthenticator(new FidoAuthenticator.ProcessFidoHelper(script));
		FidoAuthenticationCallback cb = newCallback(false);
		try {
			auth.complete(cb, "alice", null, new byte[][] { CRED_ID });
			fail("expected IOException");
		}
		catch (IOException e) {
			assertEquals("FIDO helper failed (exit 2)", e.getMessage());
			assertFalse(e.getMessage().contains("secret-signature"));
			assertFalse(e.getMessage().contains("AAAA"));
			assertFalse(e.getMessage().contains(ENROLL_TOKEN));
		}
		assertNull(cb.getCredentialId());
	}

	@Test
	public void testBlankUsernameRejected() throws Exception {
		FidoAuthenticator auth = new FidoAuthenticator((json, timeoutMs) -> {
			fail("helper should not run");
			return "{}";
		});
		try {
			auth.complete(newCallback(false), "  ", null, null);
			fail("expected IOException");
		}
		catch (IOException e) {
			assertTrue(e.getMessage().contains("User ID"));
		}
	}

	private static FidoAuthenticationCallback newCallback(boolean enroll) {
		return new FidoAuthenticationCallback(RP_ID, RP_NAME, CHALLENGE, new byte[][] { CRED_ID },
			enroll, 60);
	}

	private static JsonObject successJson(boolean create) {
		JsonObject obj = new JsonObject();
		obj.addProperty("credentialId", FidoAuthenticator.encodeBase64Url(CRED_ID));
		obj.addProperty("authenticatorData", FidoAuthenticator.encodeBase64Url(AUTH_DATA));
		obj.addProperty("clientDataJSON", FidoAuthenticator.encodeBase64Url(CLIENT_DATA));
		obj.addProperty("signature", FidoAuthenticator.encodeBase64Url(SIGNATURE));
		if (create) {
			obj.addProperty("attestationObject", FidoAuthenticator.encodeBase64Url(ATTESTATION));
		}
		return obj;
	}
}
