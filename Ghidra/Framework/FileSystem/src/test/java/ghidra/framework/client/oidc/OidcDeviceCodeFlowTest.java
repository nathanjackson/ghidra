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
package ghidra.framework.client.oidc;

import static org.junit.Assert.*;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.After;
import org.junit.Test;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import ghidra.framework.client.oidc.OidcDeviceCodeFlow.DeviceAuthorization;
import ghidra.framework.client.oidc.OidcDeviceCodeFlow.TimeSource;
import ghidra.framework.remote.OidcAuthenticationCallback;
import ghidra.util.exception.CancelledException;

public class OidcDeviceCodeFlowTest {

	private static final String CLIENT_ID = "ghidra-client";
	private static final String SCOPES = "openid profile";
	private static final String NONCE = "nonce-value";
	private static final String DEVICE_CODE = "secret-device-code-xyz";
	private static final String USER_CODE = "ABCD-EFGH";
	private static final String ID_TOKEN = "secret.id.token.xyz";
	private static final String ACCESS_TOKEN = "secret-access-token-xyz";
	private static final String REFRESH_TOKEN = "secret-refresh-token-xyz";

	private HttpServer server;
	private final List<String> deviceBodies = new CopyOnWriteArrayList<>();
	private final List<String> tokenBodies = new CopyOnWriteArrayList<>();
	private final FakeTimeSource timeSource = new FakeTimeSource();

	@After
	public void tearDown() {
		if (server != null) {
			server.stop(0);
			server = null;
		}
	}

	@Test
	public void testDeviceAuthorizationAndTokenSuccess() throws Exception {
		startIdp(deviceJson(true), exchange -> writeJson(exchange, 200, idTokenJson()));

		OidcDeviceCodeFlow flow = newFlow();
		OidcAuthenticationCallback cb = newCallback();
		String idToken = flow.complete(cb, null, null);

		assertEquals(ID_TOKEN, idToken);
		assertEquals(1, deviceBodies.size());
		Map<String, String> deviceForm = parseForm(deviceBodies.get(0));
		assertEquals(CLIENT_ID, deviceForm.get("client_id"));
		assertEquals(SCOPES, deviceForm.get("scope"));
		assertEquals(NONCE, deviceForm.get("nonce"));

		assertEquals(1, tokenBodies.size());
		Map<String, String> tokenForm = parseForm(tokenBodies.get(0));
		assertEquals(OidcDeviceCodeFlow.DEVICE_CODE_GRANT_TYPE, tokenForm.get("grant_type"));
		assertEquals(DEVICE_CODE, tokenForm.get("device_code"));
		assertEquals(CLIENT_ID, tokenForm.get("client_id"));
		assertFalse("grant_type must not be device_code",
			"device_code".equals(tokenForm.get("grant_type")));
	}

	@Test
	public void testExactDeviceCodeGrantTypeEncoding() throws Exception {
		startIdp(deviceJson(true), exchange -> writeJson(exchange, 200, idTokenJson()));
		newFlow().complete(newCallback(), null, null);

		String raw = tokenBodies.get(0);
		String encodedGrant = URLEncoder.encode(OidcDeviceCodeFlow.DEVICE_CODE_GRANT_TYPE,
			StandardCharsets.UTF_8);
		assertTrue(raw.contains("grant_type=" + encodedGrant));
		assertFalse(raw.contains("grant_type=device_code"));
	}

	@Test
	public void testAuthorizationPendingThenSuccess() throws Exception {
		AtomicInteger polls = new AtomicInteger();
		startIdp(deviceJson(true), exchange -> {
			if (polls.incrementAndGet() == 1) {
				writeJson(exchange, 400, "{\"error\":\"authorization_pending\"}");
			}
			else {
				writeJson(exchange, 200, idTokenJson());
			}
		});

		assertEquals(ID_TOKEN, newFlow().complete(newCallback(), null, null));
		assertEquals(2, polls.get());
	}

	@Test
	public void testDefaultIntervalIsFiveSecondsWhenOmitted() throws Exception {
		startIdp(deviceJson(false), exchange -> {
			if (tokenBodies.size() == 1) {
				writeJson(exchange, 400, "{\"error\":\"authorization_pending\"}");
			}
			else {
				writeJson(exchange, 200, idTokenJson());
			}
		});

		DeviceAuthorization auth = newFlow().requestDeviceAuthorization(newCallback());
		assertEquals(5, auth.getIntervalSeconds());
		newFlow().pollForIdToken(newCallback(), auth, null);
		assertEquals(5000L, timeSource.sleptMillis());
	}

	@Test
	public void testSlowDownIncreasesIntervalByFiveSeconds() throws Exception {
		AtomicInteger polls = new AtomicInteger();
		startIdp(deviceJsonWithInterval(0), exchange -> {
			int n = polls.incrementAndGet();
			if (n == 1) {
				writeJson(exchange, 400, "{\"error\":\"slow_down\"}");
			}
			else {
				writeJson(exchange, 200, idTokenJson());
			}
		});

		newFlow().complete(newCallback(), null, null);
		assertEquals(2, polls.get());
		assertEquals(OidcDeviceCodeFlow.SLOW_DOWN_INCREMENT_SECONDS * 1000L,
			timeSource.sleptMillis());
	}

	@Test
	public void testExpiredTokenFails() throws Exception {
		startIdp(deviceJson(true),
			exchange -> writeJson(exchange, 400, "{\"error\":\"expired_token\"}"));
		try {
			newFlow().complete(newCallback(), null, null);
			fail("Expected expired_token to fail");
		}
		catch (IOException e) {
			assertTrue(e.getMessage(), e.getMessage().contains("expired"));
			assertNoSecrets(e);
		}
	}

	@Test
	public void testAccessDeniedFailsImmediately() throws Exception {
		startIdp(deviceJson(true),
			exchange -> writeJson(exchange, 400, "{\"error\":\"access_denied\"}"));
		try {
			newFlow().complete(newCallback(), null, null);
			fail("Expected access_denied to fail");
		}
		catch (IOException e) {
			assertTrue(e.getMessage(), e.getMessage().contains("denied"));
			assertEquals(0, timeSource.sleptMillis());
			assertNoSecrets(e);
		}
	}

	@Test
	public void testAuthorizationDeclinedFailsImmediately() throws Exception {
		startIdp(deviceJson(true),
			exchange -> writeJson(exchange, 400, "{\"error\":\"authorization_declined\"}"));
		try {
			newFlow().complete(newCallback(), null, null);
			fail("Expected authorization_declined to fail");
		}
		catch (IOException e) {
			assertTrue(e.getMessage(), e.getMessage().contains("denied"));
			assertNoSecrets(e);
		}
	}

	@Test
	public void testHttp4xxSurfacesErrorDescription() throws Exception {
		startIdp(deviceJson(true), exchange -> writeJson(exchange, 400,
			"{\"error\":\"invalid_grant\",\"error_description\":\"not entitled\"}"));
		try {
			newFlow().complete(newCallback(), null, null);
			fail("Expected HTTP 4xx to fail");
		}
		catch (IOException e) {
			assertTrue(e.getMessage(), e.getMessage().contains("invalid_grant"));
			assertTrue(e.getMessage(), e.getMessage().contains("not entitled"));
			assertNoSecrets(e);
		}
	}

	@Test
	public void testMissingIdTokenFailsAndOmitsTokens() throws Exception {
		startIdp(deviceJson(true), exchange -> writeJson(exchange, 200,
			"{\"access_token\":\"" + ACCESS_TOKEN + "\",\"refresh_token\":\"" + REFRESH_TOKEN +
				"\",\"token_type\":\"Bearer\"}"));
		try {
			newFlow().complete(newCallback(), null, null);
			fail("Expected missing id_token to fail");
		}
		catch (IOException e) {
			assertTrue(e.getMessage(), e.getMessage().contains("id_token"));
			assertNoSecrets(e);
		}
	}

	@Test
	public void testMissingDeviceEndpointFails() throws Exception {
		OidcAuthenticationCallback cb = new OidcAuthenticationCallback("https://idp.example.test",
			CLIENT_ID, "  ", "https://idp.example.test/token", SCOPES, NONCE, "challenge", 30,
			"Example");
		try {
			newFlow().requestDeviceAuthorization(cb);
			fail("Expected missing device endpoint to fail");
		}
		catch (IOException e) {
			assertTrue(e.getMessage(), e.getMessage().contains("device authorization endpoint"));
			assertNoSecrets(e);
		}
	}

	@Test
	public void testTimeoutUsesMinOfLoginTimeoutAndExpiresIn() throws Exception {
		startIdp(deviceJsonWithExpires(30),
			exchange -> writeJson(exchange, 400, "{\"error\":\"authorization_pending\"}"));
		OidcAuthenticationCallback cb = newCallback(2);
		try {
			newFlow().complete(cb, null, null);
			fail("Expected timeout");
		}
		catch (IOException e) {
			assertTrue(e.getMessage(), e.getMessage().contains("timed out"));
			assertNoSecrets(e);
		}
		assertTrue("timeout should be loginTimeoutSeconds (2s), not expires_in (30s)",
			timeSource.nowMillis() < 1_000_000L + 30_000L);
		assertTrue(timeSource.nowMillis() >= 1_000_000L + 2_000L);
	}

	@Test
	public void testTimeoutHonorsExpiresInWhenShorterThanLoginTimeout() throws Exception {
		startIdp(deviceJsonWithExpires(1),
			exchange -> writeJson(exchange, 400, "{\"error\":\"authorization_pending\"}"));
		OidcAuthenticationCallback cb = newCallback(60);
		try {
			newFlow().complete(cb, null, null);
			fail("Expected timeout");
		}
		catch (IOException e) {
			assertTrue(e.getMessage(), e.getMessage().contains("timed out"));
		}
		assertTrue(timeSource.nowMillis() >= 1_000_000L + 1_000L);
		assertTrue("timeout should be expires_in (1s), not loginTimeout (60s)",
			timeSource.nowMillis() < 1_000_000L + 60_000L);
	}

	@Test
	public void testCancelStopsPoll() throws Exception {
		CountDownLatch polling = new CountDownLatch(1);
		startIdp(deviceJsonWithInterval(60), exchange -> {
			polling.countDown();
			writeJson(exchange, 400, "{\"error\":\"authorization_pending\"}");
		});

		OidcDeviceCodeFlow flow = new OidcDeviceCodeFlow(plainHttpClient());
		AtomicReference<Exception> error = new AtomicReference<>();
		Thread thread = new Thread(() -> {
			try {
				flow.complete(newCallback(), null, null);
				fail("Expected cancellation");
			}
			catch (CancelledException e) {
				// expected
			}
			catch (Exception e) {
				error.set(e);
			}
		});
		thread.start();
		assertTrue("poll did not start", polling.await(5, TimeUnit.SECONDS));
		flow.cancel();
		thread.join(2000);
		assertFalse("poll did not stop after cancel", thread.isAlive());
		assertNull(error.get());
	}

	@Test
	public void testInterruptStopsPoll() throws Exception {
		CountDownLatch polling = new CountDownLatch(1);
		startIdp(deviceJsonWithInterval(60), exchange -> {
			polling.countDown();
			writeJson(exchange, 400, "{\"error\":\"authorization_pending\"}");
		});

		OidcDeviceCodeFlow flow = new OidcDeviceCodeFlow(plainHttpClient());
		AtomicReference<Exception> error = new AtomicReference<>();
		Thread thread = new Thread(() -> {
			try {
				flow.complete(newCallback(), null, null);
				fail("Expected cancellation");
			}
			catch (CancelledException e) {
				// expected
			}
			catch (Exception e) {
				error.set(e);
			}
		});
		thread.start();
		assertTrue("poll did not start", polling.await(5, TimeUnit.SECONDS));
		thread.interrupt();
		thread.join(2000);
		assertFalse("poll did not stop after interrupt", thread.isAlive());
		assertNull(error.get());
	}

	@Test
	public void testCancelDuringDeviceAuthorizationIsCancelledException() throws Exception {
		CountDownLatch entered = new CountDownLatch(1);
		CountDownLatch release = new CountDownLatch(1);
		server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
		server.createContext("/device", exchange -> {
			exchange.getRequestBody().readAllBytes();
			entered.countDown();
			try {
				release.await(5, TimeUnit.SECONDS);
			}
			catch (InterruptedException e) {
				Thread.currentThread().interrupt();
			}
			exchange.sendResponseHeaders(500, -1);
			exchange.close();
		});
		server.start();

		OidcDeviceCodeFlow flow = new OidcDeviceCodeFlow(plainHttpClient());
		AtomicReference<Exception> error = new AtomicReference<>();
		Thread thread = new Thread(() -> {
			try {
				flow.requestDeviceAuthorization(newCallback());
				fail("Expected cancellation");
			}
			catch (CancelledException e) {
				// expected — not wrapped as IOException
			}
			catch (Exception e) {
				error.set(e);
			}
		});
		thread.start();
		assertTrue("device authorization did not start", entered.await(5, TimeUnit.SECONDS));
		flow.cancel();
		thread.join(3000);
		release.countDown();
		assertFalse("device authorization did not stop after cancel", thread.isAlive());
		assertNull(error.get() == null ? null : error.get().toString(), error.get());
	}

	@Test
	public void testNonLoopbackHttpRejected() throws Exception {
		OidcAuthenticationCallback cb = new OidcAuthenticationCallback("https://idp.example.test",
			CLIENT_ID, "http://example.test/device", "http://example.test/token", SCOPES, NONCE,
			"challenge", 30, "Example");
		try {
			newFlow().requestDeviceAuthorization(cb);
			fail("Expected non-loopback HTTP to fail");
		}
		catch (IOException e) {
			assertTrue(e.getMessage(), e.getMessage().contains("https"));
		}
	}

	@Test
	public void testFormatSignInMessagePrefersVerificationUriComplete() {
		DeviceAuthorization auth = new DeviceAuthorization(DEVICE_CODE, USER_CODE,
			"https://login.example.com/device",
			"https://login.example.com/device?user_code=ABCD-EFGH", 1800, 5);
		String text = OidcDeviceCodeFlow.formatSignInMessage(auth);
		assertTrue(text.contains("Ghidra Server OIDC sign-in required"));
		assertTrue(text.contains("Open: https://login.example.com/device?user_code=ABCD-EFGH"));
		assertTrue(text.contains(
			"(or visit https://login.example.com/device and enter code ABCD-EFGH)"));
		assertTrue(text.contains("Waiting for authorization..."));
		assertFalse(text.contains(DEVICE_CODE));
	}

	@Test
	public void testDeviceAuthorizationToStringOmitsSecrets() {
		DeviceAuthorization auth = new DeviceAuthorization(DEVICE_CODE, USER_CODE,
			"https://login.example.com/device", null, 1800, 5);
		String text = auth.toString();
		assertFalse(text.contains(DEVICE_CODE));
		assertFalse(text.contains(USER_CODE));
	}

	@Test
	public void testRedirectsAreNotFollowed() throws Exception {
		server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
		server.createContext("/device", exchange -> {
			exchange.getResponseHeaders().add("Location", issuer() + "/other");
			exchange.sendResponseHeaders(302, -1);
			exchange.close();
		});
		server.createContext("/other",
			exchange -> writeJson(exchange, 200, deviceJson(true)));
		server.start();

		OidcAuthenticationCallback cb = newCallback();
		try {
			newFlow().requestDeviceAuthorization(cb);
			fail("Expected redirect to fail");
		}
		catch (IOException e) {
			assertFalse(e.getMessage().contains(DEVICE_CODE));
		}
	}

	private OidcDeviceCodeFlow newFlow() {
		return new OidcDeviceCodeFlow(plainHttpClient(), timeSource);
	}

	private OidcAuthenticationCallback newCallback() {
		return newCallback(30);
	}

	private OidcAuthenticationCallback newCallback(int loginTimeoutSeconds) {
		return new OidcAuthenticationCallback("https://idp.example.test", CLIENT_ID,
			issuer() + "/device", issuer() + "/token", SCOPES, NONCE, "challenge",
			loginTimeoutSeconds, "Example");
	}

	private String issuer() {
		return "http://127.0.0.1:" + server.getAddress().getPort();
	}

	private void startIdp(String deviceResponse, TokenHandler tokenHandler) throws IOException {
		server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
		server.createContext("/device", exchange -> {
			deviceBodies.add(readBody(exchange));
			writeJson(exchange, 200, deviceResponse);
		});
		server.createContext("/token", exchange -> {
			tokenBodies.add(readBody(exchange));
			tokenHandler.handle(exchange);
		});
		server.start();
	}

	private static String deviceJson(boolean includeInterval) {
		StringBuilder json = new StringBuilder();
		json.append("{\"device_code\":\"").append(DEVICE_CODE).append("\"");
		json.append(",\"user_code\":\"").append(USER_CODE).append("\"");
		json.append(",\"verification_uri\":\"http://127.0.0.1/device\"");
		json.append(",\"verification_uri_complete\":\"http://127.0.0.1/device?user_code=");
		json.append(USER_CODE).append("\"");
		json.append(",\"expires_in\":1800");
		if (includeInterval) {
			json.append(",\"interval\":0");
		}
		json.append("}");
		return json.toString();
	}

	private static String deviceJsonWithInterval(int interval) {
		return deviceJson(false).replace("}", ",\"interval\":" + interval + "}");
	}

	private static String deviceJsonWithExpires(int expiresIn) {
		return deviceJsonWithInterval(1).replace("\"expires_in\":1800",
			"\"expires_in\":" + expiresIn);
	}

	private static String idTokenJson() {
		return "{\"id_token\":\"" + ID_TOKEN + "\",\"access_token\":\"" + ACCESS_TOKEN +
			"\",\"refresh_token\":\"" + REFRESH_TOKEN + "\",\"token_type\":\"Bearer\"}";
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

	private static String readBody(HttpExchange exchange) throws IOException {
		return new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
	}

	private static Map<String, String> parseForm(String body) {
		Map<String, String> values = new LinkedHashMap<>();
		if (body == null || body.isBlank()) {
			return values;
		}
		for (String pair : body.split("&")) {
			int eq = pair.indexOf('=');
			String name = eq < 0 ? pair : pair.substring(0, eq);
			String value = eq < 0 ? "" : pair.substring(eq + 1);
			values.put(URLDecoder.decode(name, StandardCharsets.UTF_8),
				URLDecoder.decode(value, StandardCharsets.UTF_8));
		}
		return values;
	}

	private static void assertNoSecrets(Throwable error) {
		String text = String.valueOf(error.getMessage());
		assertFalse(text.contains(DEVICE_CODE));
		assertFalse(text.contains(ID_TOKEN));
		assertFalse(text.contains(ACCESS_TOKEN));
		assertFalse(text.contains(REFRESH_TOKEN));
		if (error.getCause() != null && error.getCause() != error) {
			String cause = String.valueOf(error.getCause().getMessage());
			assertFalse(cause.contains(DEVICE_CODE));
			assertFalse(cause.contains(ID_TOKEN));
			assertFalse(cause.contains(ACCESS_TOKEN));
			assertFalse(cause.contains(REFRESH_TOKEN));
		}
	}

	private static HttpClient plainHttpClient() {
		return HttpClient.newBuilder()
				.followRedirects(HttpClient.Redirect.NEVER)
				.connectTimeout(Duration.ofSeconds(5))
				.build();
	}

	@FunctionalInterface
	private interface TokenHandler {
		void handle(HttpExchange exchange) throws IOException;
	}

	static final class FakeTimeSource implements TimeSource {
		private long now = 1_000_000L;
		private final List<Long> sleeps = new ArrayList<>();

		@Override
		public synchronized long currentTimeMillis() {
			return now;
		}

		@Override
		public synchronized void sleep(long millis) {
			sleeps.add(millis);
			now += millis;
		}

		synchronized long sleptMillis() {
			long total = 0;
			for (Long slice : sleeps) {
				total += slice;
			}
			return total;
		}

		synchronized long nowMillis() {
			return now;
		}
	}
}
