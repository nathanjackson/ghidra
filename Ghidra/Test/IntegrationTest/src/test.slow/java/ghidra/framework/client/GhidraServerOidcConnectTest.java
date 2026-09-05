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

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.*;
import org.junit.experimental.categories.Category;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import generic.test.category.PortSensitiveCategory;
import ghidra.framework.model.ServerInfo;
import ghidra.framework.remote.RemoteRepositoryServerHandle;
import ghidra.net.DefaultKeyManagerFactory;
import ghidra.server.remote.ServerTestUtil;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;

/**
 * Slow IntegrationTest: mock IdP device-code grant, Ghidra Server {@code -a5},
 * and client login through {@link ServerConnectTask}.
 */
@Category(PortSensitiveCategory.class)
public class GhidraServerOidcConnectTest extends AbstractGhidraHeadlessIntegrationTest {

	private static final String CLIENT_ID = "ghidra-test";
	private static final String KID = "test-rsa";
	private static final String DEVICE_CODE = "test-device-code";
	private static final String USER_CODE = "ABCD-EFGH";
	private static final String PREFERRED_USERNAME = "Alice@Example.COM";
	private static final String MAPPED_USERNAME = "alice";

	private File serverRoot;
	private HttpServer idp;
	private RSAKey rsaKey;
	private final AtomicReference<String> capturedNonce = new AtomicReference<>();

	@Before
	public void setUp() throws Exception {
		System.clearProperty(DefaultKeyManagerFactory.KEYSTORE_PATH_PROPERTY);
	}

	@After
	public void tearDown() throws Exception {
		closeAllWindows();
		killServer();
		stopIdp();
		ClientUtil.clearRepositoryAdapter("localhost", ServerTestUtil.GHIDRA_TEST_SERVER_PORT);
	}

	@Test
	public void testDeviceCodeConnectThroughServerConnectTask() throws Exception {
		rsaKey = new RSAKeyGenerator(2048).keyID(KID)
				.keyUse(KeyUse.SIGNATURE)
				.algorithm(JWSAlgorithm.RS256)
				.generate();
		startIdp();

		serverRoot = new File(getTestDirectoryPath(), "OidcTestServer");
		FileUtilities.deleteDir(serverRoot);
		FileUtilities.mkdirs(serverRoot);
		ServerTestUtil.createUsers(serverRoot.getAbsolutePath());

		File jwksFile = writeJwks();
		File oidcFile = writeOidcConfig(jwksFile);

		ServerTestUtil.setLocalUser("test");
		HeadlessClientAuthenticator.installHeadlessClientAuthenticator(null, null, false);

		ServerTestUtil.startServer(serverRoot.getAbsolutePath(),
			ServerTestUtil.GHIDRA_TEST_SERVER_PORT, 5, false, false, false, "-oidc",
			oidcFile.getAbsolutePath(), "-autoProvision");

		ServerConnectTask task = new ServerConnectTask(
			new ServerInfo("localhost", ServerTestUtil.GHIDRA_TEST_SERVER_PORT), false);
		task.run(TaskMonitor.DUMMY);

		if (task.getException() != null) {
			throw new AssertionError("OIDC server connect failed", task.getException());
		}
		RemoteRepositoryServerHandle handle = task.getRepositoryServerHandle();
		assertNotNull("ServerConnectTask should return a repository handle", handle);
		assertEquals(MAPPED_USERNAME, handle.getUser());
		assertFalse(handle.isReadOnly());
	}

	private void killServer() {
		if (serverRoot == null) {
			return;
		}
		ServerTestUtil.disposeServer();
		FileUtilities.deleteDir(serverRoot);
		serverRoot = null;
	}

	private void stopIdp() {
		if (idp != null) {
			idp.stop(0);
			idp = null;
		}
	}

	private void startIdp() throws IOException {
		idp = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
		idp.createContext("/.well-known/openid-configuration", this::handleDiscovery);
		idp.createContext("/jwks", this::handleJwks);
		idp.createContext("/device", this::handleDevice);
		idp.createContext("/token", this::handleToken);
		idp.start();
	}

	private String issuer() {
		return "http://127.0.0.1:" + idp.getAddress().getPort();
	}

	private File writeJwks() throws IOException {
		File jwksFile = new File(serverRoot, "jwks.json");
		Files.writeString(jwksFile.toPath(), new JWKSet(rsaKey.toPublicJWK()).toString(),
			StandardCharsets.UTF_8);
		return jwksFile;
	}

	private File writeOidcConfig(File jwksFile) throws IOException {
		File oidcFile = new File(serverRoot, "oidc.conf");
		String issuer = issuer();
		String contents = "issuer=" + issuer + "\n" +
			"clientId=" + CLIENT_ID + "\n" +
			"jwksFile=" + jwksFile.getAbsolutePath().replace('\\', '/') + "\n" +
			"deviceAuthorizationEndpoint=" + issuer + "/device\n" +
			"tokenEndpoint=" + issuer + "/token\n" +
			"loginTimeoutSeconds=60\n";
		Files.writeString(oidcFile.toPath(), contents, StandardCharsets.UTF_8);
		return oidcFile;
	}

	private void handleDiscovery(HttpExchange exchange) throws IOException {
		String issuer = issuer();
		writeJson(exchange, 200,
			"{\"issuer\":\"" + issuer + "\"," +
				"\"device_authorization_endpoint\":\"" + issuer + "/device\"," +
				"\"token_endpoint\":\"" + issuer + "/token\"," +
				"\"jwks_uri\":\"" + issuer + "/jwks\"," +
				"\"token_endpoint_auth_methods_supported\":[\"none\"]," +
				"\"id_token_signing_alg_values_supported\":[\"RS256\"]}");
	}

	private void handleJwks(HttpExchange exchange) throws IOException {
		writeJson(exchange, 200, new JWKSet(rsaKey.toPublicJWK()).toString());
	}

	private void handleDevice(HttpExchange exchange) throws IOException {
		Map<String, String> form = readForm(exchange);
		capturedNonce.set(form.get("nonce"));
		String issuer = issuer();
		writeJson(exchange, 200,
			"{\"device_code\":\"" + DEVICE_CODE + "\",\"user_code\":\"" + USER_CODE + "\"," +
				"\"verification_uri\":\"" + issuer + "/device\"," +
				"\"verification_uri_complete\":\"" + issuer + "/device?user_code=" + USER_CODE +
				"\",\"expires_in\":1800,\"interval\":0}");
	}

	private void handleToken(HttpExchange exchange) throws IOException {
		readForm(exchange);
		try {
			writeJson(exchange, 200, "{\"id_token\":\"" + signIdToken() + "\"}");
		}
		catch (Exception e) {
			writeJson(exchange, 500, "{\"error\":\"server_error\"}");
		}
	}

	private String signIdToken() throws Exception {
		Date now = new Date();
		JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder().issuer(issuer())
				.audience(CLIENT_ID)
				.subject("user-1")
				.issueTime(now)
				.expirationTime(new Date(now.getTime() + 300_000L))
				.claim("preferred_username", PREFERRED_USERNAME);
		String nonce = capturedNonce.get();
		if (nonce != null && !nonce.isBlank()) {
			claims.claim("nonce", nonce);
		}
		SignedJWT jwt = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(KID).build(), claims.build());
		jwt.sign(new RSASSASigner(rsaKey));
		return jwt.serialize();
	}

	private static Map<String, String> readForm(HttpExchange exchange) throws IOException {
		String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
		Map<String, String> form = new LinkedHashMap<>();
		if (body.isBlank()) {
			return form;
		}
		for (String pair : body.split("&")) {
			int eq = pair.indexOf('=');
			if (eq < 0) {
				continue;
			}
			String name = URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8);
			String value = URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
			form.put(name, value);
		}
		return form;
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
}
