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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class OidcConfigTest {

	@Rule
	public TemporaryFolder tempFolder = new TemporaryFolder();

	@Test
	public void testDefaults() throws Exception {
		OidcConfig config = load(
			"issuer=https://issuer.example.test\n" +
				"clientId=ghidra-client\n");

		assertEquals("https://issuer.example.test", config.getIssuer());
		assertEquals("ghidra-client", config.getClientId());
		assertEquals("preferred_username", config.getUsernameClaim());
		assertEquals(List.of("email", "sub"), config.getUsernameClaimFallbacks());
		assertEquals("openid profile", config.getScopes());
		assertEquals(900, config.getLoginTimeoutSeconds());
		assertEquals(600, config.getMaxTokenAgeSeconds());
		assertEquals(60, config.getClockSkewSeconds());
		assertTrue(config.getAllowedSigningAlgs().contains("RS256"));
		assertEquals("ghidra-client", config.getAudience());
		assertFalse(config.isAirGap());
	}

	@Test
	public void testOpenidAddedWhenOmitted() throws Exception {
		OidcConfig config = load(
			"issuer=https://issuer.example.test\n" +
				"clientId=ghidra-client\n" +
				"scopes=profile email\n");
		assertEquals("openid profile email", config.getScopes());
	}

	@Test
	public void testAirGapRequiresJwksAndEndpoints() throws Exception {
		File jwks = tempFolder.newFile("jwks.json");
		Files.writeString(jwks.toPath(), "{\"keys\":[]}", StandardCharsets.UTF_8);
		OidcConfig config = load(
			"issuer=https://issuer.example.test\n" +
				"clientId=ghidra-client\n" +
				"jwksFile=" + jwks.getAbsolutePath() + "\n" +
				"deviceAuthorizationEndpoint=https://issuer.example.test/device\n" +
				"tokenEndpoint=https://issuer.example.test/token\n");
		assertTrue(config.isAirGap());
		assertEquals(jwks.getAbsolutePath(), config.getJwksFile().getAbsolutePath());
	}

	@Test
	public void testHttpNonLoopbackIssuerRejected() throws Exception {
		try {
			load("issuer=http://idp.example.test\nclientId=ghidra-client\n");
			fail("Expected http issuer to be rejected");
		}
		catch (IllegalArgumentException e) {
			assertTrue(e.getMessage(), e.getMessage().contains("https"));
		}
	}

	@Test
	public void testHttpLoopbackIssuerAccepted() throws Exception {
		OidcConfig config = load(
			"issuer=http://127.0.0.1:8080/realms/ghidra\n" +
				"clientId=ghidra-client\n");
		assertEquals("http://127.0.0.1:8080/realms/ghidra", config.getIssuer());
	}

	@Test
	public void testMissingIssuerRejected() throws Exception {
		try {
			load("clientId=ghidra-client\n");
			fail("Expected missing issuer to be rejected");
		}
		catch (IllegalArgumentException e) {
			assertTrue(e.getMessage(), e.getMessage().contains("issuer"));
		}
	}

	@Test
	public void testMissingClientIdRejected() throws Exception {
		try {
			load("issuer=https://issuer.example.test\n");
			fail("Expected missing clientId to be rejected");
		}
		catch (IllegalArgumentException e) {
			assertTrue(e.getMessage(), e.getMessage().contains("clientId"));
		}
	}

	@Test
	public void testHmacSigningAlgRejected() throws Exception {
		try {
			load("issuer=https://issuer.example.test\nclientId=c\nallowedSigningAlgs=HS256\n");
			fail("Expected HS256 to be rejected");
		}
		catch (IllegalArgumentException e) {
			assertTrue(e.getMessage(), e.getMessage().contains("not allowed"));
		}
	}

	@Test
	public void testUnsupportedUsernameTransformRejected() throws Exception {
		try {
			load("issuer=https://issuer.example.test\nclientId=c\nusernameTransform=none\n");
			fail("Expected unsupported transform to be rejected");
		}
		catch (IllegalArgumentException e) {
			assertTrue(e.getMessage(), e.getMessage().contains("lowercase"));
		}
	}

	private OidcConfig load(String contents) throws Exception {
		File file = tempFolder.newFile();
		Files.writeString(file.toPath(), contents, StandardCharsets.UTF_8);
		return OidcConfig.load(file);
	}
}
