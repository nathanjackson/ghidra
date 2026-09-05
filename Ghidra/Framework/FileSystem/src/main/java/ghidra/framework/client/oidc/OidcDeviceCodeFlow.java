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

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpClient.Redirect;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicBoolean;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.framework.remote.OidcAuthenticationCallback;
import ghidra.net.HttpClients;
import ghidra.util.exception.CancelledException;

/**
 * RFC 8628 OAuth 2.0 device authorization grant used by GUI and headless
 * Ghidra Server clients. Token POSTs never follow redirects.
 */
public class OidcDeviceCodeFlow {

	public static final String DEVICE_CODE_GRANT_TYPE =
		"urn:ietf:params:oauth:grant-type:device_code";
	public static final int DEFAULT_POLL_INTERVAL_SECONDS = 5;
	public static final int HTTP_TIMEOUT_SECONDS = 10;
	public static final int SLOW_DOWN_INCREMENT_SECONDS = 5;

	private static HttpClient oidcPostClient;

	private final HttpClient httpClient;
	private final TimeSource timeSource;
	private final AtomicBoolean cancelled = new AtomicBoolean();
	private volatile Thread workerThread;

	/**
	 * Construct a flow using a long-lived HTTP client that never follows redirects.
	 *
	 * @throws IOException if the HTTP client cannot be created
	 */
	public OidcDeviceCodeFlow() throws IOException {
		this(getOidcPostClient(), SYSTEM_TIME);
	}

	/**
	 * Construct a flow using the given HTTP client.
	 *
	 * @param httpClient client used for device and token POSTs
	 */
	public OidcDeviceCodeFlow(HttpClient httpClient) {
		this(httpClient, SYSTEM_TIME);
	}

	OidcDeviceCodeFlow(HttpClient httpClient, TimeSource timeSource) {
		if (httpClient == null) {
			throw new IllegalArgumentException("httpClient is required");
		}
		if (timeSource == null) {
			throw new IllegalArgumentException("timeSource is required");
		}
		this.httpClient = httpClient;
		this.timeSource = timeSource;
	}

	private static synchronized HttpClient getOidcPostClient() throws IOException {
		if (oidcPostClient == null) {
			oidcPostClient = HttpClients.newHttpClientBuilder()
					.followRedirects(Redirect.NEVER)
					.connectTimeout(Duration.ofSeconds(HTTP_TIMEOUT_SECONDS))
					.build();
		}
		return oidcPostClient;
	}

	/**
	 * Stop an in-progress device authorization or poll. Interrupts the worker
	 * thread so an in-flight HTTP send or sleep does not wait out the request timeout.
	 */
	public void cancel() {
		cancelled.set(true);
		Thread t = workerThread;
		if (t != null) {
			t.interrupt();
		}
	}

	/**
	 * Request a device code, notify the listener, then poll until an ID token is issued.
	 *
	 * @param oidcCb OIDC callback with provider metadata
	 * @param listener notified after a device code is issued (may be null)
	 * @param extraCancelled optional extra cancellation check (may be null)
	 * @return ID token
	 * @throws IOException if authorization fails
	 * @throws CancelledException if the poll is cancelled
	 */
	public String complete(OidcAuthenticationCallback oidcCb, DeviceAuthorizationListener listener,
			Cancelled extraCancelled) throws IOException, CancelledException {
		DeviceAuthorization authorization =
			requestDeviceAuthorization(oidcCb, extraCancelled);
		if (listener != null) {
			listener.deviceAuthorizationStarted(authorization);
		}
		return pollForIdToken(oidcCb, authorization, extraCancelled);
	}

	/**
	 * POST the device authorization request and return the user-facing codes.
	 *
	 * @param oidcCb OIDC callback with provider metadata
	 * @return device authorization details
	 * @throws IOException if the request fails or the response is invalid
	 * @throws CancelledException if the request is cancelled
	 */
	public DeviceAuthorization requestDeviceAuthorization(OidcAuthenticationCallback oidcCb)
			throws IOException, CancelledException {
		return requestDeviceAuthorization(oidcCb, null);
	}

	DeviceAuthorization requestDeviceAuthorization(OidcAuthenticationCallback oidcCb,
			Cancelled extraCancelled) throws IOException, CancelledException {
		if (oidcCb == null) {
			throw new IllegalArgumentException("oidcCb is required");
		}
		String endpoint = oidcCb.getDeviceAuthorizationEndpoint();
		if (isBlank(endpoint)) {
			throw new IOException(
				"OIDC device authorization endpoint is missing. The identity provider " +
					"must advertise device_authorization_endpoint.");
		}
		URI uri = requireHttpsUrl(endpoint, "device authorization endpoint");
		String clientId = oidcCb.getClientId();
		if (isBlank(clientId)) {
			throw new IOException("OIDC client_id is missing");
		}
		String scopes = oidcCb.getScopes();
		if (isBlank(scopes)) {
			scopes = "openid";
		}

		StringBuilder form = new StringBuilder();
		appendForm(form, "client_id", clientId);
		appendForm(form, "scope", scopes);
		if (!isBlank(oidcCb.getNonce())) {
			appendForm(form, "nonce", oidcCb.getNonce());
		}

		JsonObject json =
			postForm(uri, form.toString(), "OIDC device authorization", extraCancelled);
		String deviceCode = jsonString(json, "device_code");
		String userCode = jsonString(json, "user_code");
		String verificationUri = jsonString(json, "verification_uri");
		if (isBlank(deviceCode) || isBlank(userCode) || isBlank(verificationUri)) {
			throw new IOException("OIDC device authorization response is missing required fields");
		}
		String verificationUriComplete = jsonString(json, "verification_uri_complete");
		int expiresIn = jsonInt(json, "expires_in", 0);
		int interval = json.has("interval") && !json.get("interval").isJsonNull()
				? jsonInt(json, "interval", DEFAULT_POLL_INTERVAL_SECONDS)
				: DEFAULT_POLL_INTERVAL_SECONDS;
		if (interval < 0) {
			interval = DEFAULT_POLL_INTERVAL_SECONDS;
		}
		return new DeviceAuthorization(deviceCode, userCode, verificationUri,
			verificationUriComplete, expiresIn, interval);
	}

	/**
	 * Poll the token endpoint until an ID token is issued, the login times out,
	 * or the flow is cancelled.
	 *
	 * @param oidcCb OIDC callback with provider metadata
	 * @param authorization device authorization details
	 * @param extraCancelled optional extra cancellation check (may be null)
	 * @return ID token
	 * @throws IOException if authorization fails
	 * @throws CancelledException if the poll is cancelled
	 */
	public String pollForIdToken(OidcAuthenticationCallback oidcCb,
			DeviceAuthorization authorization, Cancelled extraCancelled)
			throws IOException, CancelledException {
		if (oidcCb == null) {
			throw new IllegalArgumentException("oidcCb is required");
		}
		if (authorization == null) {
			throw new IllegalArgumentException("authorization is required");
		}
		String endpoint = oidcCb.getTokenEndpoint();
		if (isBlank(endpoint)) {
			throw new IOException("OIDC token endpoint is missing");
		}
		URI uri = requireHttpsUrl(endpoint, "token endpoint");
		String clientId = oidcCb.getClientId();
		if (isBlank(clientId)) {
			throw new IOException("OIDC client_id is missing");
		}

		int timeoutSeconds = oidcCb.getLoginTimeoutSeconds();
		if (authorization.getExpiresInSeconds() > 0) {
			if (timeoutSeconds <= 0) {
				timeoutSeconds = authorization.getExpiresInSeconds();
			}
			else {
				timeoutSeconds = Math.min(timeoutSeconds, authorization.getExpiresInSeconds());
			}
		}
		if (timeoutSeconds <= 0) {
			throw new IOException("OIDC login timeout is not set");
		}
		long deadlineMs = timeSource.currentTimeMillis() + (timeoutSeconds * 1000L);
		int intervalSeconds = authorization.getIntervalSeconds();

		StringBuilder form = new StringBuilder();
		appendForm(form, "grant_type", DEVICE_CODE_GRANT_TYPE);
		appendForm(form, "device_code", authorization.deviceCode);
		appendForm(form, "client_id", clientId);
		String body = form.toString();

		while (true) {
			checkCancelled(extraCancelled);
			if (timeSource.currentTimeMillis() >= deadlineMs) {
				throw new IOException("OIDC authorization timed out");
			}

			TokenPollResult result = pollOnce(uri, body, extraCancelled);
			if (result.idToken != null) {
				return result.idToken;
			}
			if (result.retry) {
				if ("slow_down".equals(result.error)) {
					intervalSeconds += SLOW_DOWN_INCREMENT_SECONDS;
				}
				waitForInterval(intervalSeconds, deadlineMs, extraCancelled);
				continue;
			}
			throw new IOException(result.failureMessage);
		}
	}

	/**
	 * Build the user-facing device-code sign-in instructions.
	 *
	 * @param authorization device authorization details
	 * @return text to print or display
	 */
	public static String formatSignInMessage(DeviceAuthorization authorization) {
		String verificationUri = authorization.getVerificationUri();
		String complete = authorization.getVerificationUriComplete();
		String openUri = !isBlank(complete) ? complete : verificationUri;
		StringBuilder buf = new StringBuilder();
		buf.append("Ghidra Server OIDC sign-in required\n");
		buf.append("Open: ").append(openUri).append('\n');
		buf.append("(or visit ").append(verificationUri).append(" and enter code ");
		buf.append(authorization.getUserCode()).append(")\n");
		buf.append("Waiting for authorization...");
		return buf.toString();
	}

	private TokenPollResult pollOnce(URI uri, String form, Cancelled extraCancelled)
			throws IOException, CancelledException {
		HttpResponse<String> response = sendForm(uri, form, "OIDC token", extraCancelled);
		int status = response.statusCode();
		JsonObject json = parseJsonObject(response.body(), "OIDC token");

		String idToken = jsonString(json, "id_token");
		if (!isBlank(idToken)) {
			return TokenPollResult.idToken(idToken);
		}

		String error = jsonString(json, "error");
		String description = jsonString(json, "error_description");
		if ("authorization_pending".equals(error)) {
			return TokenPollResult.retry(error);
		}
		if ("slow_down".equals(error)) {
			return TokenPollResult.retry(error);
		}
		if ("expired_token".equals(error)) {
			return TokenPollResult.fail("OIDC device code expired");
		}
		if ("access_denied".equals(error) || "authorization_declined".equals(error)) {
			return TokenPollResult.fail("OIDC authorization was denied");
		}
		if (status >= 400 && status < 500) {
			return TokenPollResult.fail(formatOauthError(error, description, status));
		}
		if (!isBlank(error)) {
			return TokenPollResult.fail(formatOauthError(error, description, status));
		}
		if (status == 200) {
			return TokenPollResult.fail("OIDC token response did not include an id_token");
		}
		return TokenPollResult.fail("OIDC token request failed: HTTP " + status);
	}

	private JsonObject postForm(URI uri, String form, String what, Cancelled extraCancelled)
			throws IOException, CancelledException {
		HttpResponse<String> response = sendForm(uri, form, what, extraCancelled);
		int status = response.statusCode();
		JsonObject json = parseJsonObject(response.body(), what);
		if (status >= 200 && status < 300) {
			return json;
		}
		String error = jsonString(json, "error");
		String description = jsonString(json, "error_description");
		throw new IOException(formatOauthError(error, description, status));
	}

	private HttpResponse<String> sendForm(URI uri, String form, String what,
			Cancelled extraCancelled) throws IOException, CancelledException {
		HttpRequest request = HttpRequest.newBuilder(uri)
				.timeout(Duration.ofSeconds(HTTP_TIMEOUT_SECONDS))
				.header("Content-Type", "application/x-www-form-urlencoded")
				.header("Accept", "application/json")
				.POST(HttpRequest.BodyPublishers.ofString(form, StandardCharsets.UTF_8))
				.build();
		Thread previous = workerThread;
		workerThread = Thread.currentThread();
		try {
			checkCancelled(extraCancelled);
			return httpClient.send(request, BodyHandlers.ofString(StandardCharsets.UTF_8));
		}
		catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			throw new CancelledException("OIDC authorization cancelled");
		}
		catch (IOException e) {
			checkCancelled(extraCancelled);
			throw new IOException(what + " request failed", e);
		}
		finally {
			workerThread = previous;
		}
	}

	private void waitForInterval(int intervalSeconds, long deadlineMs, Cancelled extraCancelled)
			throws IOException, CancelledException {
		long waitMs = intervalSeconds * 1000L;
		long remaining = deadlineMs - timeSource.currentTimeMillis();
		if (remaining <= 0) {
			throw new IOException("OIDC authorization timed out");
		}
		if (waitMs > remaining) {
			waitMs = remaining;
		}
		long waitUntil = timeSource.currentTimeMillis() + waitMs;
		while (true) {
			checkCancelled(extraCancelled);
			long now = timeSource.currentTimeMillis();
			if (now >= deadlineMs) {
				throw new IOException("OIDC authorization timed out");
			}
			long slice = waitUntil - now;
			if (slice <= 0) {
				return;
			}
			Thread previous = workerThread;
			workerThread = Thread.currentThread();
			try {
				timeSource.sleep(Math.min(slice, 200));
			}
			catch (InterruptedException e) {
				Thread.currentThread().interrupt();
				throw new CancelledException("OIDC authorization cancelled");
			}
			finally {
				workerThread = previous;
			}
		}
	}

	private void checkCancelled(Cancelled extraCancelled) throws CancelledException {
		if (cancelled.get() || Thread.currentThread().isInterrupted() ||
			(extraCancelled != null && extraCancelled.isCancelled())) {
			throw new CancelledException("OIDC authorization cancelled");
		}
	}

	private static JsonObject parseJsonObject(String body, String what) throws IOException {
		if (body == null || body.isBlank()) {
			throw new IOException(what + " response is empty");
		}
		try {
			JsonElement root = JsonParser.parseString(body);
			if (root == null || !root.isJsonObject()) {
				throw new IOException(what + " response is not a JSON object");
			}
			return root.getAsJsonObject();
		}
		catch (IOException e) {
			throw e;
		}
		catch (RuntimeException e) {
			throw new IOException(what + " response is not valid JSON");
		}
	}

	private static String formatOauthError(String error, String description, int status) {
		if (!isBlank(error) && !isBlank(description)) {
			return "OIDC authorization failed: " + error + " (" + description + ")";
		}
		if (!isBlank(error)) {
			return "OIDC authorization failed: " + error;
		}
		if (!isBlank(description)) {
			return "OIDC authorization failed: " + description;
		}
		return "OIDC authorization failed: HTTP " + status;
	}

	private static String jsonString(JsonObject json, String key) {
		if (json == null || !json.has(key) || json.get(key).isJsonNull()) {
			return null;
		}
		try {
			JsonElement value = json.get(key);
			if (!value.isJsonPrimitive() || !value.getAsJsonPrimitive().isString()) {
				return null;
			}
			String text = value.getAsString();
			return isBlank(text) ? null : text;
		}
		catch (RuntimeException e) {
			return null;
		}
	}

	private static int jsonInt(JsonObject json, String key, int defaultValue) {
		if (json == null || !json.has(key) || json.get(key).isJsonNull()) {
			return defaultValue;
		}
		try {
			JsonElement value = json.get(key);
			if (value.isJsonPrimitive() && value.getAsJsonPrimitive().isNumber()) {
				return value.getAsInt();
			}
			if (value.isJsonPrimitive() && value.getAsJsonPrimitive().isString()) {
				return Integer.parseInt(value.getAsString().trim());
			}
		}
		catch (RuntimeException e) {
			return defaultValue;
		}
		return defaultValue;
	}

	private static void appendForm(StringBuilder form, String name, String value) {
		if (form.length() > 0) {
			form.append('&');
		}
		form.append(URLEncoder.encode(name, StandardCharsets.UTF_8));
		form.append('=');
		form.append(URLEncoder.encode(value == null ? "" : value, StandardCharsets.UTF_8));
	}

	private static URI requireHttpsUrl(String value, String name) throws IOException {
		URI uri;
		try {
			uri = URI.create(value.trim());
		}
		catch (IllegalArgumentException e) {
			throw new IOException(name + " is not a valid URL");
		}
		if (uri.getScheme() == null || uri.getHost() == null) {
			throw new IOException(name + " is not a valid URL");
		}
		String scheme = uri.getScheme();
		if ("https".equalsIgnoreCase(scheme)) {
			return uri;
		}
		if ("http".equalsIgnoreCase(scheme) && isLoopbackHost(uri.getHost())) {
			return uri;
		}
		throw new IOException(name + " must be an https URL");
	}

	private static boolean isLoopbackHost(String host) {
		if (host == null || host.isBlank()) {
			return false;
		}
		if (host.startsWith("[") && host.endsWith("]") && host.length() > 2) {
			host = host.substring(1, host.length() - 1);
		}
		return "127.0.0.1".equals(host) || "localhost".equalsIgnoreCase(host) || "::1".equals(host);
	}

	private static boolean isBlank(String value) {
		return value == null || value.trim().isEmpty();
	}

	/**
	 * Device authorization details to display and poll with.
	 */
	public static final class DeviceAuthorization {
		private final String deviceCode;
		private final String userCode;
		private final String verificationUri;
		private final String verificationUriComplete;
		private final int expiresInSeconds;
		private final int intervalSeconds;

		DeviceAuthorization(String deviceCode, String userCode, String verificationUri,
				String verificationUriComplete, int expiresInSeconds, int intervalSeconds) {
			this.deviceCode = deviceCode;
			this.userCode = userCode;
			this.verificationUri = verificationUri;
			this.verificationUriComplete = verificationUriComplete;
			this.expiresInSeconds = expiresInSeconds;
			this.intervalSeconds = intervalSeconds;
		}

		public String getUserCode() {
			return userCode;
		}

		public String getVerificationUri() {
			return verificationUri;
		}

		public String getVerificationUriComplete() {
			return verificationUriComplete;
		}

		public int getExpiresInSeconds() {
			return expiresInSeconds;
		}

		public int getIntervalSeconds() {
			return intervalSeconds;
		}

		@Override
		public String toString() {
			return "DeviceAuthorization[verificationUri=" + verificationUri +
				", expiresInSeconds=" + expiresInSeconds + ", intervalSeconds=" + intervalSeconds +
				"]";
		}
	}

	/**
	 * Receives device authorization details so a UI can prompt the user.
	 */
	@FunctionalInterface
	public interface DeviceAuthorizationListener {
		void deviceAuthorizationStarted(DeviceAuthorization authorization);
	}

	/**
	 * Additional cancellation check consulted during polling.
	 */
	@FunctionalInterface
	public interface Cancelled {
		boolean isCancelled();
	}

	interface TimeSource {
		long currentTimeMillis();

		void sleep(long millis) throws InterruptedException;
	}

	static final TimeSource SYSTEM_TIME = new TimeSource() {
		@Override
		public long currentTimeMillis() {
			return System.currentTimeMillis();
		}

		@Override
		public void sleep(long millis) throws InterruptedException {
			Thread.sleep(millis);
		}
	};

	private static final class TokenPollResult {
		private final String idToken;
		private final boolean retry;
		private final String error;
		private final String failureMessage;

		private TokenPollResult(String idToken, boolean retry, String error,
				String failureMessage) {
			this.idToken = idToken;
			this.retry = retry;
			this.error = error;
			this.failureMessage = failureMessage;
		}

		static TokenPollResult idToken(String idToken) {
			return new TokenPollResult(idToken, false, null, null);
		}

		static TokenPollResult retry(String error) {
			return new TokenPollResult(null, true, error, null);
		}

		static TokenPollResult fail(String failureMessage) {
			return new TokenPollResult(null, false, null, failureMessage);
		}
	}
}
