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

import java.util.concurrent.atomic.AtomicLong;

import org.junit.Test;

import ghidra.server.security.oidc.OidcLoginChallengeStore.IssuedChallenge;

public class OidcLoginChallengeStoreTest {

	@Test
	public void testConsumeOnce() {
		OidcLoginChallengeStore store = newStore(1000, 8);
		IssuedChallenge issued = store.issue();
		assertNotNull(issued.nonce);
		assertNotNull(issued.loginChallenge);
		assertEquals(issued.nonce, store.consume(issued.loginChallenge));
		assertNull(store.consume(issued.loginChallenge));
	}

	@Test
	public void testUnknownChallengeFailsClosed() {
		OidcLoginChallengeStore store = newStore(1000, 8);
		assertNull(store.consume("not-issued"));
		assertNull(store.consume(null));
		assertNull(store.consume(""));
	}

	@Test
	public void testExpiredChallengeFailsClosed() {
		AtomicLong now = new AtomicLong(1_000L);
		OidcLoginChallengeStore store = new OidcLoginChallengeStore(100, 8, now::get);
		IssuedChallenge issued = store.issue();
		now.addAndGet(100);
		assertNull(store.consume(issued.loginChallenge));
	}

	@Test
	public void testCapRefusesNewChallenges() {
		AtomicLong now = new AtomicLong(1_000L);
		OidcLoginChallengeStore store = new OidcLoginChallengeStore(1_000, 2, now::get);
		store.issue();
		store.issue();
		try {
			store.issue();
			fail("Expected in-flight cap to refuse a new challenge");
		}
		catch (IllegalStateException e) {
			assertTrue(e.getMessage(), e.getMessage().contains("in-flight"));
		}
		assertEquals(2, store.size());
	}

	@Test
	public void testExpiredEntriesFreedBeforeCap() {
		AtomicLong now = new AtomicLong(1_000L);
		OidcLoginChallengeStore store = new OidcLoginChallengeStore(50, 1, now::get);
		store.issue();
		now.addAndGet(50);
		IssuedChallenge issued = store.issue();
		assertEquals(issued.nonce, store.consume(issued.loginChallenge));
	}

	private static OidcLoginChallengeStore newStore(long ttlMillis, int maxInFlight) {
		return new OidcLoginChallengeStore(ttlMillis, maxInFlight, System::currentTimeMillis);
	}
}
