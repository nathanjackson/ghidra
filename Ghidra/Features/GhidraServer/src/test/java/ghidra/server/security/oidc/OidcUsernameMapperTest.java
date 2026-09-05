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

import java.util.List;

import javax.security.auth.login.LoginException;

import org.junit.Test;

import com.nimbusds.jwt.JWTClaimsSet;

import ghidra.server.UserManager;

public class OidcUsernameMapperTest {

	@Test
	public void testMixedCaseUpnUsesLocalPart() throws Exception {
		OidcUsernameMapper mapper = defaultMapper();
		JWTClaimsSet claims = baseClaims()
				.claim("preferred_username", "JSmith@CORP.example.com")
				.build();
		assertEquals("jsmith", mapper.map(claims));
	}

	@Test
	public void testEmailLocalPart() throws Exception {
		OidcUsernameMapper mapper = defaultMapper();
		JWTClaimsSet claims = baseClaims()
				.claim("preferred_username", "!!!")
				.claim("email", "Alice.Bob@Example.COM")
				.build();
		assertEquals("alice.bob", mapper.map(claims));
	}

	@Test
	public void testInvalidThenNextClaim() throws Exception {
		OidcUsernameMapper mapper = defaultMapper();
		JWTClaimsSet claims = baseClaims()
				.claim("preferred_username", "!!!")
				.claim("email", "good.user@example.com")
				.build();
		assertEquals("good.user", mapper.map(claims));
	}

	@Test
	public void testSubHashLastResort() throws Exception {
		OidcUsernameMapper mapper =
			new OidcUsernameMapper("preferred_username", List.of("email"), null, null);
		JWTClaimsSet claims = baseClaims()
				.subject("opaque-subject")
				.claim("preferred_username", "!!!")
				.claim("email", "!!!")
				.build();
		String expected = OidcUsernameMapper.hashSubject("opaque-subject");
		assertEquals(expected, mapper.map(claims));
		assertTrue(UserManager.isValidUserName(expected));
		assertTrue(expected.startsWith("u"));
		assertEquals(17, expected.length());
	}

	@Test
	public void testAlwaysLowercase() throws Exception {
		OidcUsernameMapper mapper = defaultMapper();
		JWTClaimsSet claims = baseClaims()
				.claim("preferred_username", "John_Doe")
				.build();
		assertEquals("john_doe", mapper.map(claims));
	}

	@Test
	public void testResultAlwaysPassesIsValidUserName() throws Exception {
		OidcUsernameMapper mapper = defaultMapper();
		JWTClaimsSet claims = baseClaims()
				.claim("preferred_username", "Valid.User-Name_1")
				.build();
		String username = mapper.map(claims);
		assertTrue(UserManager.isValidUserName(username));
		assertTrue(username.length() <= OidcUsernameMapper.MAX_USERNAME_LENGTH);
	}

	@Test
	public void testLongNameTruncated() throws Exception {
		String longName = "a".repeat(80);
		OidcUsernameMapper mapper = defaultMapper();
		JWTClaimsSet claims = baseClaims().claim("preferred_username", longName).build();
		String username = mapper.map(claims);
		assertEquals(64, username.length());
		assertTrue(UserManager.isValidUserName(username));
	}

	@Test
	public void testTenantIdMismatchRejected() {
		OidcUsernameMapper mapper =
			new OidcUsernameMapper("preferred_username", List.of("email", "sub"), "tenant-a", null);
		JWTClaimsSet claims = baseClaims()
				.claim("preferred_username", "alice")
				.claim("tid", "tenant-b")
				.build();
		try {
			mapper.map(claims);
			fail("Expected tenant mismatch to fail");
		}
		catch (LoginException e) {
			assertFalse(e instanceof javax.security.auth.login.FailedLoginException);
		}
	}

	@Test
	public void testHostedDomainRequiredWhenConfigured() {
		OidcUsernameMapper mapper =
			new OidcUsernameMapper("preferred_username", List.of("email", "sub"), null,
				"example.com");
		JWTClaimsSet claims = baseClaims().claim("preferred_username", "alice").build();
		try {
			mapper.map(claims);
			fail("Expected missing hd to fail");
		}
		catch (LoginException e) {
			assertFalse(e instanceof javax.security.auth.login.FailedLoginException);
		}
	}

	@Test
	public void testSanitizeEmailPlusTag() {
		assertEquals("alice.bobtag", OidcUsernameMapper.sanitize("Alice.Bob+tag@Example.COM"));
	}

	private static OidcUsernameMapper defaultMapper() {
		return new OidcUsernameMapper("preferred_username", List.of("email", "sub"), null, null);
	}

	private static JWTClaimsSet.Builder baseClaims() {
		return new JWTClaimsSet.Builder().subject("user-1");
	}
}
