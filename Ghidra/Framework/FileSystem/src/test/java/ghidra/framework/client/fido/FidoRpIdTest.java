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

import static org.junit.Assert.*;

import org.junit.Test;

import generic.test.AbstractGenericTest;

public class FidoRpIdTest extends AbstractGenericTest {

	@Test
	public void testExactMatchIsCaseInsensitive() {
		assertTrue(FidoRpId.matchesConnectedHost("Ghidra.Example.ORG", "ghidra.example.org"));
		assertTrue(FidoRpId.matchesConnectedHost("ghidra.example.org", " ghidra.example.org "));
	}

	@Test
	public void testLoopbackAliasesMatch() {
		assertTrue(FidoRpId.matchesConnectedHost("localhost", "127.0.0.1"));
		assertTrue(FidoRpId.matchesConnectedHost("127.0.0.1", "localhost"));
		assertTrue(FidoRpId.matchesConnectedHost("localhost", "::1"));
		assertTrue(FidoRpId.matchesConnectedHost("::1", "[::1]"));
	}

	@Test
	public void testMismatchHostname() {
		assertFalse(FidoRpId.matchesConnectedHost("ghidra.corp.com", "evil.com"));
		assertFalse(FidoRpId.matchesConnectedHost("ghidra.example.org", "localhost"));
	}

	@Test
	public void testMismatchIpVersusHostname() {
		assertFalse(FidoRpId.matchesConnectedHost("ghidra.example.org", "10.0.0.5"));
		assertFalse(FidoRpId.matchesConnectedHost("10.0.0.5", "ghidra.example.org"));
	}

	@Test
	public void testNullOrMalformedFailsClosed() {
		assertFalse(FidoRpId.matchesConnectedHost(null, "ghidra.example.org"));
		assertFalse(FidoRpId.matchesConnectedHost("ghidra.example.org", null));
		assertFalse(FidoRpId.matchesConnectedHost("https://ghidra.example.org", "ghidra.example.org"));
		assertFalse(FidoRpId.matchesConnectedHost("ghidra.example.org:13100", "ghidra.example.org"));
	}

	@Test
	public void testNormalizeRejectsSchemeAndPort() {
		try {
			FidoRpId.normalize("https://ghidra.example.org");
			fail("expected IllegalArgumentException");
		}
		catch (IllegalArgumentException e) {
			assertTrue(e.getMessage().contains("hostname"));
		}
		try {
			FidoRpId.normalize("ghidra.example.org:13100");
			fail("expected IllegalArgumentException");
		}
		catch (IllegalArgumentException e) {
			assertTrue(e.getMessage().contains("hostname"));
		}
	}

	@Test
	public void testOriginFor() {
		assertEquals("http://localhost", FidoRpId.originFor("localhost"));
		assertEquals("http://127.0.0.1", FidoRpId.originFor("127.0.0.1"));
		assertEquals("http://[::1]", FidoRpId.originFor("::1"));
		assertEquals("https://ghidra.example.org", FidoRpId.originFor("ghidra.example.org"));
	}
}
