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
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.security.auth.callback.Callback;

import org.junit.After;
import org.junit.Test;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import ghidra.framework.client.oidc.OidcDeviceCodeFlow;
import ghidra.framework.remote.AnonymousCallback;
import ghidra.framework.remote.OidcAuthenticationCallback;

public class ClientOidcAuthenticatorTest {

	private static final String CLIENT_ID = "ghidra-client";
	private static final String ID_TOKEN = "secret.id.token.xyz";
	private static final String DEVICE_CODE = "secret-device-code-xyz";

	private HttpServer server;

	@After
	public void tearDown() {
		if (server != null) {
			server.stop(0);
			server = null;
		}
	}

	@Test
	public void testPasswordAuthenticatorReturnsFalse() throws Exception {
		PasswordClientAuthenticator auth = new PasswordClientAuthenticator("unused");
		OidcAuthenticationCallback oidc = newCallback("https://idp.example.test/device",
			"https://idp.example.test/token");
		assertFalse(auth.processOidcCallback(oidc, null, "server.example.test"));
		assertNull(oidc.getIdToken());
	}

	@Test
	public void testHeadlessMissingDeviceEndpointFailsEvenWhenPasswordPromptAllowed()
			throws Exception {
		HeadlessClientAuthenticator.installHeadlessClientAuthenticator(null, null, true);
		HeadlessClientAuthenticator auth = new HeadlessClientAuthenticator();
		OidcAuthenticationCallback oidc =
			newCallback("  ", "https://idp.example.test/token");
		try {
			auth.processOidcCallback(oidc, null, "server.example.test");
			fail("Expected missing device endpoint to fail");
		}
		catch (IOException e) {
			assertTrue(e.getMessage(), e.getMessage().contains("device authorization endpoint"));
			assertFalse(e.getMessage().contains(DEVICE_CODE));
			assertFalse(e.getMessage().contains(ID_TOKEN));
		}
		assertNull(oidc.getIdToken());
	}

	@Test
	public void testHeadlessMissingDeviceEndpointFailsWhenPasswordPromptDisallowed()
			throws Exception {
		HeadlessClientAuthenticator.installHeadlessClientAuthenticator(null, null, false);
		HeadlessClientAuthenticator auth = new HeadlessClientAuthenticator();
		try {
			auth.processOidcCallback(newCallback(null, "https://idp.example.test/token"), null,
				"server.example.test");
			fail("Expected missing device endpoint to fail");
		}
		catch (IOException e) {
			assertTrue(e.getMessage(), e.getMessage().contains("device authorization endpoint"));
		}
	}

	@Test
	public void testHeadlessPrintsSignInInstructionsToStderr() throws Exception {
		startIdp();
		OidcDeviceCodeFlow flow = new OidcDeviceCodeFlow(plainHttpClient());
		HeadlessClientAuthenticator auth = new HeadlessClientAuthenticator(flow);
		OidcAuthenticationCallback oidc =
			newCallback(issuer() + "/device", issuer() + "/token");

		ByteArrayOutputStream captured = new ByteArrayOutputStream();
		PrintStream original = System.err;
		System.setErr(new PrintStream(captured, true, StandardCharsets.UTF_8));
		try {
			assertTrue(auth.processOidcCallback(oidc, null, "server.example.test"));
		}
		finally {
			System.setErr(original);
		}

		assertEquals(ID_TOKEN, oidc.getIdToken());
		String stderr = captured.toString(StandardCharsets.UTF_8);
		assertTrue(stderr, stderr.contains("Ghidra Server OIDC sign-in required"));
		assertTrue(stderr, stderr.contains("Open: http://127.0.0.1/device?user_code=ABCD-EFGH"));
		assertTrue(stderr, stderr.contains("Waiting for authorization..."));
		assertFalse(stderr.contains(DEVICE_CODE));
		assertFalse(stderr.contains(ID_TOKEN));
	}

	@Test
	public void testClientUtilSkipsDeviceFlowWhenAnonymousRequested() throws Exception {
		AtomicBoolean called = new AtomicBoolean();
		ClientUtil.setClientAuthenticator(new RecordingAuthenticator(called, false, null));
		AnonymousCallback anonymous = new AnonymousCallback();
		anonymous.setAnonymousAccessRequested(true);
		OidcAuthenticationCallback oidc =
			newCallback("https://idp.example.test/device", "https://idp.example.test/token");

		assertTrue(ClientUtil.processOidcCallback(new Callback[] { oidc, anonymous },
			"server.example.test", null));
		assertFalse(called.get());
		assertNull(oidc.getIdToken());
	}

	@Test
	public void testClientUtilSetsIdTokenViaAuthenticator() throws Exception {
		ClientUtil.setClientAuthenticator(
			new RecordingAuthenticator(new AtomicBoolean(), true, ID_TOKEN));
		OidcAuthenticationCallback oidc =
			newCallback("https://idp.example.test/device", "https://idp.example.test/token");
		assertTrue(ClientUtil.processOidcCallback(new Callback[] { oidc }, "server.example.test",
			null));
		assertEquals(ID_TOKEN, oidc.getIdToken());
	}

	@Test
	public void testClientUtilCancelReturnsFalse() throws Exception {
		ClientUtil.setClientAuthenticator(
			new RecordingAuthenticator(new AtomicBoolean(), false, null));
		OidcAuthenticationCallback oidc =
			newCallback("https://idp.example.test/device", "https://idp.example.test/token");
		assertFalse(ClientUtil.processOidcCallback(new Callback[] { oidc }, "server.example.test",
			null));
	}

	private void startIdp() throws IOException {
		server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
		server.createContext("/device", exchange -> {
			exchange.getRequestBody().readAllBytes();
			writeJson(exchange, 200,
				"{\"device_code\":\"" + DEVICE_CODE + "\",\"user_code\":\"ABCD-EFGH\"," +
					"\"verification_uri\":\"http://127.0.0.1/device\"," +
					"\"verification_uri_complete\":\"http://127.0.0.1/device?user_code=ABCD-EFGH\"," +
					"\"expires_in\":1800,\"interval\":0}");
		});
		server.createContext("/token", exchange -> {
			exchange.getRequestBody().readAllBytes();
			writeJson(exchange, 200, "{\"id_token\":\"" + ID_TOKEN + "\"}");
		});
		server.start();
	}

	private String issuer() {
		return "http://127.0.0.1:" + server.getAddress().getPort();
	}

	private static OidcAuthenticationCallback newCallback(String device, String token) {
		return new OidcAuthenticationCallback("https://idp.example.test", CLIENT_ID, device, token,
			"openid profile", "nonce", "challenge", 30, "Example");
	}

	private static void writeJson(HttpExchange exchange, int status, String json)
			throws IOException {
		byte[] body = json.getBytes(StandardCharsets.UTF_8);
		exchange.getResponseHeaders().set("Content-Type", "application/json");
		exchange.sendResponseHeaders(status, body.length);
		try (OutputStream out = exchange.getResponseBody()) {
			out.write(body);
		}
	}

	private static HttpClient plainHttpClient() {
		return HttpClient.newBuilder()
				.followRedirects(HttpClient.Redirect.NEVER)
				.connectTimeout(Duration.ofSeconds(5))
				.build();
	}

	private static class RecordingAuthenticator extends PasswordClientAuthenticator {
		private final AtomicBoolean called;
		private final boolean result;
		private final String idToken;

		RecordingAuthenticator(AtomicBoolean called, boolean result, String idToken) {
			super("unused");
			this.called = called;
			this.result = result;
			this.idToken = idToken;
		}

		@Override
		public boolean processOidcCallback(OidcAuthenticationCallback oidcCb,
				AnonymousCallback anonymousCb, String serverName) {
			called.set(true);
			if (idToken != null) {
				oidcCb.setIdToken(idToken);
			}
			return result;
		}
	}
}
