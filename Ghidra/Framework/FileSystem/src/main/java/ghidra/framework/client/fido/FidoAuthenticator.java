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

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

import org.apache.commons.lang3.StringUtils;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.framework.Application;
import ghidra.framework.OSFileNotFoundException;
import ghidra.framework.OperatingSystem;
import ghidra.framework.remote.FidoAuthenticationCallback;
import ghidra.framework.remote.FidoRpId;

/**
 * Invokes the platform {@code ghidra-fido} helper to complete a FIDO2 assertion
 * or enrollment. The helper protocol is one JSON object on stdin and one JSON
 * object on stdout.
 */
public class FidoAuthenticator {

	static final String HELPER_NAME = "ghidra-fido";
	static final String OP_ASSERT = "assert";
	static final String OP_CREATE = "create";

	private static final int DEFAULT_TIMEOUT_MS = 60_000;
	private static final int MIN_TIMEOUT_MS = 5_000;
	private static final int MAX_TIMEOUT_MS = 300_000;
	private static final int MAX_HELPER_ERROR_CHARS = 256;

	private final FidoHelper helper;

	/**
	 * Locate {@code ghidra-fido} via {@link Application#getOSFile(String)} and spawn it.
	 */
	public FidoAuthenticator() {
		this(new ProcessFidoHelper());
	}

	/**
	 * @param helper helper used to exchange JSON; tests inject a fake
	 */
	public FidoAuthenticator(FidoHelper helper) {
		if (helper == null) {
			throw new IllegalArgumentException("helper is required");
		}
		this.helper = helper;
	}

	/**
	 * Abort an in-flight helper invocation.
	 */
	public void cancel() {
		helper.cancel();
	}

	/**
	 * Run assert or create and store the result on {@code fidoCb}.
	 * {@code enrollToken} non-blank selects create; otherwise assert.
	 * {@code connectedHost} is the hostname the client used to reach the server.
	 * The helper is not spawned unless it matches {@code fidoCb.getRpId()}
	 * (loopback aliases are equivalent). A null host is treated as the callback
	 * rpId (unit tests of the helper protocol).
	 * @param fidoCb callback to fill
	 * @param userName login name
	 * @param enrollToken one-time admin enroll token, or null/blank for assert
	 * @param allowCredentials credential ids for assert; may be null or empty
	 * @param pin security-key PIN for libfido2; may be null or empty. Not logged.
	 * @param connectedHost host the client connected to; null uses callback rpId
	 * @throws IOException if the helper fails
	 */
	public void complete(FidoAuthenticationCallback fidoCb, String userName, String enrollToken,
			byte[][] allowCredentials, char[] pin, String connectedHost) throws IOException {
		if (fidoCb == null) {
			throw new IllegalArgumentException("fidoCb is required");
		}
		if (StringUtils.isBlank(userName)) {
			throw new IOException("User ID is required");
		}
		String host = StringUtils.isBlank(connectedHost) ? fidoCb.getRpId() : connectedHost;
		if (!FidoRpId.matchesConnectedHost(fidoCb.getRpId(), host)) {
			throw new IOException(FidoRpId.MISMATCH_MESSAGE);
		}
		boolean create = !StringUtils.isBlank(enrollToken);
		int timeoutMs = timeoutMs(fidoCb.getTimeoutSeconds());
		String request = encodeRequest(create ? OP_CREATE : OP_ASSERT, fidoCb, userName,
			allowCredentials, timeoutMs, pin);
		try {
			String responseJson = helper.execute(request, timeoutMs);
			applyResponse(fidoCb, responseJson, create, enrollToken);
		}
		catch (IOException e) {
			throw sanitize(e, pin);
		}
	}

	static int timeoutMs(int timeoutSeconds) {
		if (timeoutSeconds <= 0) {
			return DEFAULT_TIMEOUT_MS;
		}
		long ms = timeoutSeconds * 1000L;
		if (ms < MIN_TIMEOUT_MS) {
			return MIN_TIMEOUT_MS;
		}
		if (ms > MAX_TIMEOUT_MS) {
			return MAX_TIMEOUT_MS;
		}
		return (int) ms;
	}

	static String encodeRequest(String op, FidoAuthenticationCallback fidoCb, String userName,
			byte[][] allowCredentials, int timeoutMs, char[] pin) {
		JsonObject obj = new JsonObject();
		obj.addProperty("op", op);
		obj.addProperty("rpId", fidoCb.getRpId());
		if (fidoCb.getRpName() != null) {
			obj.addProperty("rpName", fidoCb.getRpName());
		}
		obj.addProperty("origin", FidoRpId.originFor(fidoCb.getRpId()));
		obj.addProperty("challenge", encodeBase64Url(fidoCb.getChallenge()));
		obj.addProperty("timeoutMs", timeoutMs);
		obj.addProperty("userName", userName);
		obj.addProperty("userId", encodeBase64Url(userIdFor(userName)));
		JsonArray allow = new JsonArray();
		if (allowCredentials != null) {
			for (byte[] id : allowCredentials) {
				if (id != null && id.length > 0) {
					allow.add(encodeBase64Url(id));
				}
			}
		}
		obj.add("allowCredentials", allow);
		if (pin != null && pin.length > 0) {
			obj.addProperty("pin", new String(pin));
		}
		return obj.toString();
	}

	static void applyResponse(FidoAuthenticationCallback fidoCb, String responseJson,
			boolean create, String enrollToken) throws IOException {
		if (StringUtils.isBlank(responseJson)) {
			throw new IOException("FIDO helper returned no result");
		}
		JsonObject obj;
		try {
			JsonElement element = JsonParser.parseString(responseJson);
			if (element == null || !element.isJsonObject()) {
				throw new IOException("FIDO helper returned invalid JSON");
			}
			obj = element.getAsJsonObject();
		}
		catch (IOException e) {
			throw e;
		}
		catch (RuntimeException e) {
			throw new IOException("FIDO helper returned invalid JSON");
		}
		String error = stringField(obj, "error");
		if (!StringUtils.isBlank(error)) {
			throw new IOException(error.trim());
		}
		byte[] credentialId = requiredBytes(obj, "credentialId");
		byte[] authenticatorData = optionalBytes(obj, "authenticatorData");
		byte[] clientDataJSON = requiredBytes(obj, "clientDataJSON");
		byte[] signature = optionalBytes(obj, "signature");
		fidoCb.setAssertion(credentialId, authenticatorData, clientDataJSON, signature);
		if (create) {
			byte[] attestation = requiredBytes(obj, "attestationObject");
			fidoCb.setAttestationObject(attestation);
			fidoCb.setEnrollToken(enrollToken);
		}
	}

	static byte[] userIdFor(String userName) {
		try {
			return MessageDigest.getInstance("SHA-256")
					.digest(userName.getBytes(StandardCharsets.UTF_8));
		}
		catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("SHA-256 not available", e);
		}
	}

	static String encodeBase64Url(byte[] data) {
		if (data == null) {
			return "";
		}
		return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
	}

	static byte[] decodeBase64Url(String data) {
		if (data == null || data.isBlank()) {
			return null;
		}
		try {
			return Base64.getUrlDecoder().decode(data);
		}
		catch (IllegalArgumentException e) {
			return null;
		}
	}

	private static String stringField(JsonObject obj, String name) {
		if (!obj.has(name) || obj.get(name).isJsonNull()) {
			return null;
		}
		try {
			return obj.get(name).getAsString();
		}
		catch (RuntimeException e) {
			return null;
		}
	}

	private static byte[] requiredBytes(JsonObject obj, String name) throws IOException {
		String value = stringField(obj, name);
		if (StringUtils.isBlank(value)) {
			throw new IOException("FIDO helper omitted " + name);
		}
		byte[] decoded = decodeBase64Url(value);
		if (decoded == null) {
			throw new IOException("FIDO helper returned invalid " + name);
		}
		return decoded;
	}

	private static byte[] optionalBytes(JsonObject obj, String name) throws IOException {
		String value = stringField(obj, name);
		if (StringUtils.isBlank(value)) {
			return null;
		}
		byte[] decoded = decodeBase64Url(value);
		if (decoded == null) {
			throw new IOException("FIDO helper returned invalid " + name);
		}
		return decoded;
	}

	private static IOException sanitize(IOException e, char[] pin) {
		String msg = safeHelperError(e.getMessage(), pin);
		return new IOException(msg);
	}

	static String safeHelperError(String msg) {
		return safeHelperError(msg, null);
	}

	static String safeHelperError(String msg, char[] pin) {
		if (msg == null || msg.isBlank()) {
			return "FIDO helper failed";
		}
		String trimmed = msg.trim();
		if (pin != null && pin.length > 0 && trimmed.contains(new String(pin))) {
			return "FIDO helper failed";
		}
		if (trimmed.length() > MAX_HELPER_ERROR_CHARS || trimmed.indexOf('{') >= 0) {
			return "FIDO helper failed";
		}
		return trimmed;
	}

	/**
	 * Locate the platform helper binary.
	 * @return helper executable
	 * @throws IOException if the helper is not present
	 */
	public static File findHelperBinary() throws IOException {
		String name = HELPER_NAME;
		if (OperatingSystem.CURRENT_OPERATING_SYSTEM == OperatingSystem.WINDOWS) {
			name += ".exe";
		}
		try {
			return Application.getOSFile(name);
		}
		catch (OSFileNotFoundException e) {
			throw new IOException("FIDO helper not found: " + name, e);
		}
	}

	/**
	 * Spawns {@code os/<platform>/ghidra-fido}, writes one JSON request to stdin,
	 * and reads one JSON object from stdout.
	 */
	public static class ProcessFidoHelper implements FidoHelper {

		private final File binary;
		private volatile Process process;

		public ProcessFidoHelper() {
			this(null);
		}

		/**
		 * @param binary helper executable, or null to locate via {@link Application#getOSFile}
		 */
		public ProcessFidoHelper(File binary) {
			this.binary = binary;
		}

		@Override
		public String execute(String requestJson, int timeoutMs) throws IOException {
			File exe = binary != null ? binary : findHelperBinary();
			ProcessBuilder pb = new ProcessBuilder(exe.getAbsolutePath());
			pb.redirectError(ProcessBuilder.Redirect.PIPE);
			Process p = pb.start();
			process = p;
			StreamCollector stdout = new StreamCollector(p.getInputStream());
			StreamCollector stderr = new StreamCollector(p.getErrorStream());
			stdout.start();
			stderr.start();
			try {
				try (OutputStream out = p.getOutputStream()) {
					out.write(requestJson.getBytes(StandardCharsets.UTF_8));
				}
				waitFor(p, timeoutMs);
				stdout.join(1000);
				stderr.join(1000);
				if (stdout.ioError != null) {
					throw stdout.ioError;
				}
				int exit = p.exitValue();
				String error = errorFrom(stdout.text, exit);
				if (error != null) {
					throw new IOException(error);
				}
				return stdout.text;
			}
			catch (InterruptedException e) {
				Thread.currentThread().interrupt();
				destroyQuietly(p);
				throw new IOException("FIDO authentication cancelled");
			}
			finally {
				destroyQuietly(p);
				process = null;
			}
		}

		@Override
		public void cancel() {
			Process p = process;
			if (p != null) {
				destroyQuietly(p);
			}
		}

		private static void waitFor(Process p, int timeoutMs) throws InterruptedException,
				IOException {
			long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(Math.max(timeoutMs, MIN_TIMEOUT_MS));
			while (true) {
				long remaining = deadline - System.nanoTime();
				if (remaining <= 0) {
					destroyQuietly(p);
					throw new IOException("FIDO helper timed out");
				}
				if (p.waitFor(Math.min(200, TimeUnit.NANOSECONDS.toMillis(remaining) + 1),
					TimeUnit.MILLISECONDS)) {
					return;
				}
				if (Thread.currentThread().isInterrupted()) {
					destroyQuietly(p);
					throw new InterruptedException();
				}
			}
		}

		private static String errorFrom(String stdout, int exit) {
			String jsonError = jsonError(stdout);
			if (!StringUtils.isBlank(jsonError)) {
				return safeHelperError(jsonError);
			}
			if (exit != 0) {
				return "FIDO helper failed (exit " + exit + ")";
			}
			return null;
		}

		private static String jsonError(String stdout) {
			if (StringUtils.isBlank(stdout)) {
				return null;
			}
			try {
				JsonElement element = JsonParser.parseString(stdout);
				if (element != null && element.isJsonObject()) {
					JsonObject obj = element.getAsJsonObject();
					if (obj.has("error") && !obj.get("error").isJsonNull()) {
						String err = obj.get("error").getAsString();
						return StringUtils.isBlank(err) ? "FIDO helper reported an error" : err;
					}
				}
			}
			catch (RuntimeException e) {
				// not JSON
			}
			return null;
		}

		private static class StreamCollector extends Thread {
			private final InputStream in;
			volatile String text = "";
			volatile IOException ioError;

			StreamCollector(InputStream in) {
				super("ghidra-fido-io");
				setDaemon(true);
				this.in = in;
			}

			@Override
			public void run() {
				try {
					ByteArrayOutputStream bos = new ByteArrayOutputStream();
					byte[] buf = new byte[4096];
					int n;
					int total = 0;
					while ((n = in.read(buf)) >= 0) {
						total += n;
						if (total > 256 * 1024) {
							ioError = new IOException("FIDO helper output too large");
							return;
						}
						bos.write(buf, 0, n);
					}
					text = bos.toString(StandardCharsets.UTF_8);
				}
				catch (IOException e) {
					ioError = e;
				}
			}
		}

		private static void destroyQuietly(Process p) {
			if (p == null || !p.isAlive()) {
				return;
			}
			p.destroy();
			try {
				if (!p.waitFor(500, TimeUnit.MILLISECONDS)) {
					p.destroyForcibly();
				}
			}
			catch (InterruptedException e) {
				p.destroyForcibly();
				Thread.currentThread().interrupt();
			}
		}
	}
}
