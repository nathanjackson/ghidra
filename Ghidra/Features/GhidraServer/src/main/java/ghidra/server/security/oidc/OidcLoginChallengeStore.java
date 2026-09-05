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

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.LongSupplier;

import generic.random.SecureRandomFactory;

/**
 * One-time OIDC login challenges with a configurable TTL and in-flight cap.
 */
public final class OidcLoginChallengeStore {

	public static final int MAX_IN_FLIGHT = 1024;
	private static final int TOKEN_BYTES = 32;

	private final long ttlMillis;
	private final int maxInFlight;
	private final LongSupplier clock;
	private final Map<String, IssuedChallenge> cache = new ConcurrentHashMap<>();
	private final Object issueLock = new Object();
	private final ScheduledExecutorService scheduler;

	public OidcLoginChallengeStore(int ttlSeconds) {
		this(ttlSeconds * 1000L, MAX_IN_FLIGHT, System::currentTimeMillis);
	}

	OidcLoginChallengeStore(long ttlMillis, int maxInFlight, LongSupplier clock) {
		if (ttlMillis <= 0) {
			throw new IllegalArgumentException("ttlMillis must be > 0");
		}
		if (maxInFlight <= 0) {
			throw new IllegalArgumentException("maxInFlight must be > 0");
		}
		if (clock == null) {
			throw new IllegalArgumentException("clock is required");
		}
		this.ttlMillis = ttlMillis;
		this.maxInFlight = maxInFlight;
		this.clock = clock;
		this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
			Thread thread = new Thread(r, "OidcLoginChallengeStore");
			thread.setDaemon(true);
			return thread;
		});
		scheduler.scheduleAtFixedRate(this::cleanup, 5, 5, TimeUnit.SECONDS);
	}

	/**
	 * Issue a nonce and one-time login challenge.
	 *
	 * @return issued nonce and challenge
	 * @throws IllegalStateException if the in-flight cap has been reached
	 */
	public IssuedChallenge issue() {
		synchronized (issueLock) {
			cleanupUnlocked();
			if (cache.size() >= maxInFlight) {
				throw new IllegalStateException("Too many in-flight OIDC logins");
			}
			String nonce = randomToken();
			String challenge = randomToken();
			IssuedChallenge issued = new IssuedChallenge(nonce, challenge, clock.getAsLong());
			cache.put(challenge, issued);
			return issued;
		}
	}

	/**
	 * Consume a previously issued challenge. Returns the original nonce when
	 * the challenge is valid; {@code null} on miss, expiry, or replay.
	 *
	 * @param loginChallenge challenge previously issued by {@link #issue()}
	 * @return nonce bound to the challenge, or {@code null}
	 */
	public String consume(String loginChallenge) {
		if (loginChallenge == null || loginChallenge.isEmpty()) {
			return null;
		}
		IssuedChallenge issued = cache.remove(loginChallenge);
		if (issued == null) {
			return null;
		}
		if (clock.getAsLong() - issued.issuedAtMs >= ttlMillis) {
			return null;
		}
		return issued.nonce;
	}

	int size() {
		return cache.size();
	}

	private void cleanup() {
		synchronized (issueLock) {
			cleanupUnlocked();
		}
	}

	private void cleanupUnlocked() {
		long now = clock.getAsLong();
		cache.entrySet().removeIf(e -> now - e.getValue().issuedAtMs >= ttlMillis);
	}

	private static String randomToken() {
		SecureRandom random = SecureRandomFactory.getSecureRandom();
		byte[] bytes = new byte[TOKEN_BYTES];
		random.nextBytes(bytes);
		return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
	}

	public static final class IssuedChallenge {
		public final String nonce;
		public final String loginChallenge;
		final long issuedAtMs;

		IssuedChallenge(String nonce, String loginChallenge, long issuedAtMs) {
			this.nonce = nonce;
			this.loginChallenge = loginChallenge;
			this.issuedAtMs = issuedAtMs;
		}
	}
}
