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
package ghidra.server.security.oidc;

import static org.junit.Assert.*;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.After;
import org.junit.Test;

import com.sun.net.httpserver.HttpServer;

import ghidra.server.security.oidc.OidcDiscoveryClient.ProviderMetadata;

public class OidcDiscoveryClientTest {

	private HttpServer server;

	@After
	public void tearDown() {
		if (server != null) {
			server.stop(0);
			server = null;
		}
	}

	@Test
	public void testDiscoveryRequiresDeviceAuthorizationEndpoint() throws Exception {
		String issuer = startDiscoveryServer(
			discoveryJson(false, true, List.of("none"), List.of("RS256")));
		OidcDiscoveryClient client = newClient();
		ProviderMetadata metadata = client.getMetadata(issuer);
		assertNull(metadata.deviceAuthorizationEndpoint);
		try {
			OidcDiscoveryClient.validateDeviceCodeSupport(metadata, Set.of("RS256", "ES256"));
			fail("Expected missing device_authorization_endpoint to fail");
		}
		catch (IOException e) {
			assertTrue(e.getMessage(), e.getMessage().contains("device_authorization_endpoint"));
			assertTrue(e.getMessage(), e.getMessage().contains("public/native"));
		}
	}

	@Test
	public void testDiscoverySuccess() throws Exception {
		String issuer = startDiscoveryServer(
			discoveryJson(true, true, List.of("none", "client_secret_basic"), List.of("RS256")));
		ProviderMetadata metadata = newClient().getMetadata(issuer);
		Set<String> algs =
			OidcDiscoveryClient.validateDeviceCodeSupport(metadata, Set.of("RS256", "ES256"));
		assertEquals(issuer + "/device", metadata.deviceAuthorizationEndpoint);
		assertEquals(issuer + "/token", metadata.tokenEndpoint);
		assertEquals("https://issuer.example.test/jwks", metadata.jwksUri);
		assertTrue(algs.contains("RS256"));
	}

	@Test
	public void testDiscoveryMissingIssuerRejected() throws Exception {
		String issuer = startDiscoveryServer(
			"{\"token_endpoint\":\"PLACEHOLDER/token\"," +
				"\"device_authorization_endpoint\":\"PLACEHOLDER/device\"," +
				"\"jwks_uri\":\"https://issuer.example.test/jwks\"}");
		try {
			newClient().getMetadata(issuer);
			fail("Expected missing discovered issuer to fail");
		}
		catch (IOException e) {
			assertTrue(e.getMessage(), e.getMessage().contains("issuer mismatch"));
		}
	}

	@Test
	public void testDiscoveryBlankIssuerRejected() throws Exception {
		String issuer = startDiscoveryServer(
			"{\"issuer\":\"  \"," +
				"\"token_endpoint\":\"PLACEHOLDER/token\"," +
				"\"device_authorization_endpoint\":\"PLACEHOLDER/device\"," +
				"\"jwks_uri\":\"https://issuer.example.test/jwks\"}");
		try {
			newClient().getMetadata(issuer);
			fail("Expected blank discovered issuer to fail");
		}
		catch (IOException e) {
			assertTrue(e.getMessage(), e.getMessage().contains("issuer mismatch"));
		}
	}

	@Test
	public void testLoopbackHttpJwksUriRejected() {
		ProviderMetadata metadata = new ProviderMetadata("http://127.0.0.1:8080",
			"http://127.0.0.1:8080/device", "http://127.0.0.1:8080/token",
			"http://127.0.0.1:8080/jwks", List.of("none"), List.of("RS256"));
		try {
			OidcDiscoveryClient.validateDeviceCodeSupport(metadata, Set.of("RS256"));
			fail("Expected loopback HTTP jwks_uri to be rejected");
		}
		catch (IOException e) {
			assertTrue(e.getMessage(), e.getMessage().contains("https"));
		}
	}

	@Test
	public void testTokenEndpointAuthMethodsMustIncludeNoneWhenPresent() throws Exception {
		ProviderMetadata metadata = new ProviderMetadata("https://issuer.example.test",
			"https://issuer.example.test/device", "https://issuer.example.test/token",
			"https://issuer.example.test/jwks", List.of("client_secret_basic"), List.of("RS256"));
		try {
			OidcDiscoveryClient.validateDeviceCodeSupport(metadata, Set.of("RS256"));
			fail("Expected missing none auth method to fail");
		}
		catch (IOException e) {
			assertTrue(e.getMessage(), e.getMessage().contains("none"));
		}
	}

	@Test
	public void testSigningAlgIntersectionRequiredWhenPresent() throws Exception {
		ProviderMetadata metadata = new ProviderMetadata("https://issuer.example.test",
			"https://issuer.example.test/device", "https://issuer.example.test/token",
			"https://issuer.example.test/jwks", List.of("none"), List.of("RS512"));
		try {
			OidcDiscoveryClient.validateDeviceCodeSupport(metadata, Set.of("RS256", "ES256"));
			fail("Expected empty alg intersection to fail");
		}
		catch (IOException e) {
			assertTrue(e.getMessage(), e.getMessage().contains("allowedSigningAlgs"));
		}
	}

	@Test
	public void testPkceNotRequired() throws Exception {
		ProviderMetadata metadata = new ProviderMetadata("https://issuer.example.test",
			"https://issuer.example.test/device", "https://issuer.example.test/token",
			"https://issuer.example.test/jwks", null, null);
		Set<String> algs =
			OidcDiscoveryClient.validateDeviceCodeSupport(metadata, Set.of("RS256"));
		assertTrue(algs.contains("RS256"));
	}

	@Test
	public void testDiscoveryCache() throws Exception {
		AtomicInteger hits = new AtomicInteger();
		String issuer = startDiscoveryServer(exchange -> {
			hits.incrementAndGet();
			String url = "http://127.0.0.1:" + server.getAddress().getPort();
			writeJson(exchange,
				discoveryJson(true, true, List.of("none"), List.of("RS256")).replace("PLACEHOLDER",
					url));
		});
		OidcDiscoveryClient client =
			new OidcDiscoveryClient(plainHttpClient(), 60_000L);
		client.getMetadata(issuer);
		client.getMetadata(issuer);
		assertEquals(1, hits.get());
	}

	private OidcDiscoveryClient newClient() {
		return new OidcDiscoveryClient(plainHttpClient());
	}

	private static HttpClient plainHttpClient() {
		return HttpClient.newBuilder()
				.connectTimeout(Duration.ofSeconds(5))
				.build();
	}

	private String startDiscoveryServer(String json) throws IOException {
		server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
		server.start();
		String issuer = "http://127.0.0.1:" + server.getAddress().getPort();
		String body = json.replace("PLACEHOLDER", issuer);
		server.createContext("/.well-known/openid-configuration",
			exchange -> writeJson(exchange, body));
		return issuer;
	}

	private String startDiscoveryServer(com.sun.net.httpserver.HttpHandler handler)
			throws IOException {
		server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
		server.createContext("/.well-known/openid-configuration", handler);
		server.start();
		return "http://127.0.0.1:" + server.getAddress().getPort();
	}

	private static void writeJson(com.sun.net.httpserver.HttpExchange exchange, String json)
			throws IOException {
		byte[] body = json.getBytes(StandardCharsets.UTF_8);
		exchange.getResponseHeaders().set("Content-Type", "application/json");
		exchange.sendResponseHeaders(200, body.length);
		try (OutputStream out = exchange.getResponseBody()) {
			out.write(body);
		}
	}

	private static String discoveryJson(boolean device, boolean token, List<String> authMethods,
			List<String> algs) {
		StringBuilder json = new StringBuilder();
		json.append("{");
		// issuer filled at request time is awkward; tests that fetch overwrite via host.
		json.append("\"issuer\":\"PLACEHOLDER\"");
		if (device) {
			json.append(",\"device_authorization_endpoint\":\"PLACEHOLDER/device\"");
		}
		if (token) {
			json.append(",\"token_endpoint\":\"PLACEHOLDER/token\"");
		}
		json.append(",\"jwks_uri\":\"https://issuer.example.test/jwks\"");
		if (authMethods != null) {
			json.append(",\"token_endpoint_auth_methods_supported\":")
					.append(toJsonArray(authMethods));
		}
		if (algs != null) {
			json.append(",\"id_token_signing_alg_values_supported\":").append(toJsonArray(algs));
		}
		json.append("}");
		return json.toString();
	}

	private static String toJsonArray(List<String> values) {
		StringBuilder buf = new StringBuilder("[");
		for (int i = 0; i < values.size(); i++) {
			if (i > 0) {
				buf.append(',');
			}
			buf.append('"').append(values.get(i)).append('"');
		}
		buf.append(']');
		return buf.toString();
	}
}
