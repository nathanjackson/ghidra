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

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.Duration;
import java.util.Date;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.login.FailedLoginException;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;

import ghidra.framework.remote.GhidraPrincipal;
import ghidra.framework.remote.OidcAuthenticationCallback;
import ghidra.server.security.AuthenticationModule;

public class OidcAuthenticationModuleTest {

	private static final String ISSUER = "https://issuer.example.test";
	private static final String CLIENT_ID = "ghidra-client";
	private static final String KID = "test-rsa";
	private static final String SUBJECT = "user-1";

	@Rule
	public TemporaryFolder tempFolder = new TemporaryFolder();

	private RSAKey rsaKey;
	private HttpServer server;

	@Before
	public void setUp() throws Exception {
		rsaKey = new RSAKeyGenerator(2048).keyID(KID)
				.keyUse(KeyUse.SIGNATURE)
				.algorithm(JWSAlgorithm.RS256)
				.generate();
	}

	@After
	public void tearDown() {
		if (server != null) {
			server.stop(0);
			server = null;
		}
	}

	@Test
	public void testCallbackFlags() throws Exception {
		OidcAuthenticationModule module = airGapModule();
		assertFalse(module.isNameCallbackAllowed());
		assertTrue(module.anonymousCallbacksAllowed());
		Callback[] callbacks = module.getAuthenticationCallbacks();
		assertEquals(1, callbacks.length);
		assertTrue(callbacks[0] instanceof OidcAuthenticationCallback);
		OidcAuthenticationCallback oidc = (OidcAuthenticationCallback) callbacks[0];
		assertEquals(ISSUER, oidc.getIssuer());
		assertEquals(CLIENT_ID, oidc.getClientId());
		assertEquals("openid profile", oidc.getScopes());
		assertNotNull(oidc.getNonce());
		assertNotNull(oidc.getLoginChallenge());
		assertEquals(900, oidc.getLoginTimeoutSeconds());
	}

	@Test
	public void testAuthenticateSuccessInjectedIdToken() throws Exception {
		OidcAuthenticationModule module = airGapModule();
		OidcAuthenticationCallback callback = callback(module);
		callback.setIdToken(sign(validClaims(callback.getNonce())
				.claim("preferred_username", "JSmith@CORP.example.com")
				.build()));

		String username = module.authenticate(null, subject(), new Callback[] { callback });
		assertEquals("jsmith", username);
		assertNull(callback.getIdToken());
	}

	@Test
	public void testUnknownUserDoesNotThrowFromModule() throws Exception {
		OidcAuthenticationModule module = airGapModule();
		OidcAuthenticationCallback callback = callback(module);
		callback.setIdToken(sign(validClaims(callback.getNonce())
				.claim("preferred_username", "nobody")
				.build()));

		String username = module.authenticate(null, subject(), new Callback[] { callback });
		assertEquals("nobody", username);
	}

	@Test
	public void testMissingCallbackRejected() throws Exception {
		OidcAuthenticationModule module = airGapModule();
		try {
			module.authenticate(null, subject(), new Callback[0]);
			fail("Expected missing callback to fail");
		}
		catch (FailedLoginException e) {
			assertTrue(e.getMessage(), e.getMessage().contains("callback"));
		}
	}

	@Test
	public void testBlankIdTokenRejectedWithoutConsumingChallenge() throws Exception {
		OidcAuthenticationModule module = airGapModule();
		OidcAuthenticationCallback callback = callback(module);
		try {
			module.authenticate(null, subject(), new Callback[] { callback });
			fail("Expected blank ID token to fail");
		}
		catch (FailedLoginException e) {
			assertTrue(e.getMessage(), e.getMessage().contains("ID token"));
		}
		callback.setIdToken(sign(validClaims(callback.getNonce())
				.claim("preferred_username", "alice")
				.build()));
		assertEquals("alice",
			module.authenticate(null, subject(), new Callback[] { callback }));
	}

	@Test
	public void testChallengeReplayRejected() throws Exception {
		OidcAuthenticationModule module = airGapModule();
		OidcAuthenticationCallback callback = callback(module);
		callback.setIdToken(sign(validClaims(callback.getNonce())
				.claim("preferred_username", "alice")
				.build()));
		assertEquals("alice",
			module.authenticate(null, subject(), new Callback[] { callback }));

		OidcAuthenticationCallback replay = new OidcAuthenticationCallback(callback.getIssuer(),
			callback.getClientId(), callback.getDeviceAuthorizationEndpoint(),
			callback.getTokenEndpoint(), callback.getScopes(), callback.getNonce(),
			callback.getLoginChallenge(), callback.getLoginTimeoutSeconds(),
			callback.getDisplayName());
		replay.setIdToken(sign(validClaims(callback.getNonce())
				.claim("preferred_username", "alice")
				.build()));
		try {
			module.authenticate(null, subject(), new Callback[] { replay });
			fail("Expected replayed challenge to fail");
		}
		catch (FailedLoginException e) {
			assertEquals("Authentication failed", e.getMessage());
		}
	}

	@Test
	public void testDiscoveryWithoutDeviceAuthorizationEndpointFailsStartup() throws Exception {
		server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
		server.start();
		String issuer = "http://127.0.0.1:" + server.getAddress().getPort();
		String json = "{" +
			"\"issuer\":\"" + issuer + "\"," +
			"\"token_endpoint\":\"" + issuer + "/token\"," +
			"\"jwks_uri\":\"" + issuer + "/jwks\"," +
			"\"token_endpoint_auth_methods_supported\":[\"none\"]," +
			"\"id_token_signing_alg_values_supported\":[\"RS256\"]" +
			"}";
		server.createContext("/.well-known/openid-configuration", exchange -> {
			byte[] body = json.getBytes(StandardCharsets.UTF_8);
			exchange.getResponseHeaders().set("Content-Type", "application/json");
			exchange.sendResponseHeaders(200, body.length);
			try (OutputStream out = exchange.getResponseBody()) {
				out.write(body);
			}
		});

		File configFile = writeConfig(
			"issuer=" + issuer + "\n" +
				"clientId=" + CLIENT_ID + "\n");
		try {
			new OidcAuthenticationModule(configFile, plainHttpClient());
			fail("Expected startup to fail without device_authorization_endpoint");
		}
		catch (IOException e) {
			assertTrue(e.getMessage(), e.getMessage().contains("device_authorization_endpoint"));
		}
	}

	@Test
	public void testMissingConfigFileRejected() {
		try {
			new OidcAuthenticationModule((File) null);
			fail("Expected missing config file to fail");
		}
		catch (IllegalArgumentException e) {
			assertTrue(e.getMessage(), e.getMessage().contains("OIDC config file"));
		}
		catch (IOException e) {
			fail("Expected IllegalArgumentException, got IOException: " + e.getMessage());
		}
	}

	private OidcAuthenticationModule airGapModule() throws Exception {
		File jwksFile = tempFolder.newFile("jwks.json");
		Files.writeString(jwksFile.toPath(), new JWKSet(rsaKey.toPublicJWK()).toString(),
			StandardCharsets.UTF_8);
		File configFile = writeConfig(
			"issuer=" + ISSUER + "\n" +
				"clientId=" + CLIENT_ID + "\n" +
				"jwksFile=" + jwksFile.getAbsolutePath() + "\n" +
				"deviceAuthorizationEndpoint=" + ISSUER + "/device\n" +
				"tokenEndpoint=" + ISSUER + "/token\n");
		return new OidcAuthenticationModule(configFile, plainHttpClient());
	}

	private File writeConfig(String contents) throws IOException {
		File file = tempFolder.newFile();
		Files.writeString(file.toPath(), contents, StandardCharsets.UTF_8);
		return file;
	}

	private static OidcAuthenticationCallback callback(AuthenticationModule module) {
		Callback[] callbacks = module.getAuthenticationCallbacks();
		return (OidcAuthenticationCallback) callbacks[0];
	}

	private static Subject subject() {
		Subject subject = new Subject();
		subject.getPrincipals().add(new GhidraPrincipal("ignored"));
		return subject;
	}

	private JWTClaimsSet.Builder validClaims(String nonce) {
		Date now = new Date();
		JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder().issuer(ISSUER)
				.audience(CLIENT_ID)
				.subject(SUBJECT)
				.issueTime(now)
				.expirationTime(new Date(now.getTime() + 300_000L));
		if (nonce != null) {
			builder.claim("nonce", nonce);
		}
		return builder;
	}

	private String sign(JWTClaimsSet claims) throws Exception {
		SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(KID).build(),
			claims);
		jwt.sign(new RSASSASigner(rsaKey));
		return jwt.serialize();
	}

	private static HttpClient plainHttpClient() {
		return HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
	}
}
