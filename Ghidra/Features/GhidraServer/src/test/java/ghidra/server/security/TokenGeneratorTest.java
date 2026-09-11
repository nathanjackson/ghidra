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
package ghidra.server.security;

import static org.junit.Assert.*;

import org.junit.After;
import org.junit.Test;

import generic.test.AbstractGenericTest;

public class TokenGeneratorTest extends AbstractGenericTest {

	@After
	public void tearDown() {
		TokenGenerator.resetForTest();
	}

	@Test
	public void testUnboundTokenMatchesNullHost() {
		byte[] token = TokenGenerator.getNewToken();
		assertTrue(TokenGenerator.hasIssuedToken(token));
		assertTrue(TokenGenerator.hasIssuedForClient(token, null));
		assertTrue(TokenGenerator.hasIssuedForClient(token, "other.example"));
		assertTrue(TokenGenerator.isValidToken(token));
		assertFalse(TokenGenerator.hasIssuedToken(token));
	}

	@Test
	public void testBoundTokenRejectsOtherHostWithoutConsuming() {
		byte[] token = TokenGenerator.getNewTokenForClient("client-a.example");
		assertTrue(TokenGenerator.hasIssuedForClient(token, "client-a.example"));
		assertFalse(TokenGenerator.hasIssuedForClient(token, "client-b.example"));
		assertFalse(TokenGenerator.hasIssuedForClient(token, null));
		assertTrue(TokenGenerator.hasIssuedForClient(token, "client-a.example"));
		assertTrue(TokenGenerator.isValidToken(token));
	}

	@Test
	public void testAllowLookupRateLimitDoesNotConsume() {
		byte[] token = TokenGenerator.getNewToken();
		for (int i = 0; i < TokenGenerator.MAX_ALLOW_LOOKUPS; i++) {
			assertTrue(TokenGenerator.recordAllowLookup(token));
		}
		assertFalse(TokenGenerator.recordAllowLookup(token));
		assertTrue(TokenGenerator.isValidToken(token));
	}

	@Test
	public void testInFlightCap() {
		for (int i = 0; i < TokenGenerator.MAX_IN_FLIGHT; i++) {
			TokenGenerator.getNewToken();
		}
		assertEquals(TokenGenerator.MAX_IN_FLIGHT, TokenGenerator.inFlightCount());
		try {
			TokenGenerator.getNewToken();
			fail("expected IllegalStateException");
		}
		catch (IllegalStateException e) {
			assertTrue(e.getMessage().contains("in-flight"));
		}
	}
}
