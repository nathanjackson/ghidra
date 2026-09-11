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

import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.*;

import generic.random.SecureRandomFactory;

public class TokenGenerator {

	private static final long MAX_TTL_MS = 60_000; // max token time-to-live 60s

	private static final int TOKEN_SIZE = 64;

	static final int MAX_IN_FLIGHT = 1024;
	static final int MAX_ALLOW_LOOKUPS = 8;

	private static CachedTokenSet tokenCache = new CachedTokenSet();

	/**
	 * {@return a single-use token byte sequence with embedded timestamp}
	 */
	static byte[] getNewToken() {
		return getNewTokenForClient(null);
	}

	/**
	 * Issue a token bound to {@code clientHost}. A null host is unbound (unit tests
	 * and PKI/SSH). Bound tokens reject allow-list lookups and consume from a
	 * different host.
	 * @param clientHost canonical RMI client host, or null
	 * @return a single-use token byte sequence with embedded timestamp
	 */
	static byte[] getNewTokenForClient(String clientHost) {
		SecureRandom random = SecureRandomFactory.getSecureRandom();
		byte[] token = new byte[TOKEN_SIZE - 8];
		random.nextBytes(token);
		byte[] stampedToken = new byte[TOKEN_SIZE];
		System.arraycopy(token, 0, stampedToken, 8, token.length);
		putLong(stampedToken, 0, (new Date()).getTime());
		tokenCache.add(stampedToken, clientHost);
		return stampedToken;
	}

	/**
	 * Determine if the specified token has not yet been consumed and is still valid.
	 * <p>
	 * NOTE: This method may only be invoked once per token after which the token will become
	 * invalid.
	 * 
	 * @param token token previously issued
	 * @return true if token is valid and now consumed
	 */
	static boolean isValidToken(byte[] token) {
		if (token == null || token.length != TOKEN_SIZE || !tokenCache.consume(token)) {
			return false;
		}
		return hasValidTimestamp(token);
	}

	/**
	 * {@return true if the token is still cached and unexpired, without consuming it}
	 * @param token token previously issued
	 */
	static boolean hasIssuedToken(byte[] token) {
		return hasIssuedForClient(token, null);
	}

	/**
	 * {@return true if the token is cached, unexpired, and issued to {@code clientHost}}
	 * Unbound tokens (null stored host) match any caller. A bound token matches
	 * only the same host. A null {@code clientHost} matches only unbound tokens.
	 */
	static boolean hasIssuedForClient(byte[] token, String clientHost) {
		if (token == null || token.length != TOKEN_SIZE) {
			return false;
		}
		TokenRecord record = tokenCache.get(token);
		if (record == null || record.expired()) {
			return false;
		}
		if (!hasValidTimestamp(token)) {
			return false;
		}
		if (record.clientHost == null) {
			return true;
		}
		return record.clientHost.equals(clientHost);
	}

	/**
	 * Count one allow-list lookup against {@code token}. {@return false} if the
	 * token is missing, expired, or already at {@link #MAX_ALLOW_LOOKUPS}.
	 * Does not consume the token.
	 */
	static boolean recordAllowLookup(byte[] token) {
		if (token == null || token.length != TOKEN_SIZE) {
			return false;
		}
		return tokenCache.recordAllowLookup(token);
	}

	static int inFlightCount() {
		return tokenCache.size();
	}

	static void resetForTest() {
		tokenCache.clear();
	}

	private static boolean hasValidTimestamp(byte[] token) {
		long issueTime = getLong(token, 0);
		if (issueTime <= 0) {
			return false;
		}
		long diff = (new Date()).getTime() - issueTime;
		return (diff >= 0 && diff < MAX_TTL_MS);
	}

	private static long getLong(byte[] data, int offset) {
		return (((long) data[offset] & 0xff) << 56) | (((long) data[++offset] & 0xff) << 48) |
			(((long) data[++offset] & 0xff) << 40) | (((long) data[++offset] & 0xff) << 32) |
			(((long) data[++offset] & 0xff) << 24) | (((long) data[++offset] & 0xff) << 16) |
			(((long) data[++offset] & 0xff) << 8) | ((long) data[++offset] & 0xff);
	}

	private static int putLong(byte[] data, int offset, long v) {
		data[offset] = (byte) (v >> 56);
		data[++offset] = (byte) (v >> 48);
		data[++offset] = (byte) (v >> 40);
		data[++offset] = (byte) (v >> 32);
		data[++offset] = (byte) (v >> 24);
		data[++offset] = (byte) (v >> 16);
		data[++offset] = (byte) (v >> 8);
		data[++offset] = (byte) v;
		return ++offset;
	}

	/**
	 * {@link Token} provides a byte array token wrapper to facilitate value-based
	 * hashcode and equality when used as a map key.
	 */
	private static class Token {
		private byte[] token;

		Token(byte[] token) {
			this.token = token;
		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + Arrays.hashCode(token);
			return result;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj)
				return true;
			if (obj == null)
				return false;
			if (getClass() != obj.getClass())
				return false;
			Token other = (Token) obj;
			return Arrays.equals(token, other.token);
		}
	}

	/**
	 * {@link CachedTokenSet} tracks timed token issuance and insures that they remain
	 * valid for one-time consumption within limited life-span.
	 */
	private static class TokenRecord {
		final long issuedAt;
		final String clientHost;
		int allowLookups;

		TokenRecord(String clientHost) {
			this.issuedAt = System.currentTimeMillis();
			this.clientHost = clientHost;
		}

		boolean expired() {
			return System.currentTimeMillis() - issuedAt >= MAX_TTL_MS;
		}
	}

	private static class CachedTokenSet {

		private final Map<Token, TokenRecord> cache = new ConcurrentHashMap<>();
		private final ScheduledExecutorService scheduler =
			Executors.newSingleThreadScheduledExecutor();

		CachedTokenSet() {
			// Perform token cleanup every 5-seconds
			scheduler.scheduleAtFixedRate(this::cleanup, 5, 5, TimeUnit.SECONDS);
		}

		synchronized void add(byte[] token, String clientHost) {
			cleanup();
			if (cache.size() >= MAX_IN_FLIGHT) {
				throw new IllegalStateException("too many in-flight authentication challenges");
			}
			cache.put(new Token(token), new TokenRecord(clientHost));
		}

		boolean consume(byte[] token) {
			TokenRecord record = cache.remove(new Token(token));
			if (record == null) {
				return false;
			}
			return !record.expired();
		}

		TokenRecord get(byte[] token) {
			return cache.get(new Token(token));
		}

		boolean recordAllowLookup(byte[] token) {
			TokenRecord record = cache.get(new Token(token));
			if (record == null || record.expired()) {
				return false;
			}
			synchronized (record) {
				if (record.allowLookups >= MAX_ALLOW_LOOKUPS) {
					return false;
				}
				record.allowLookups++;
				return true;
			}
		}

		int size() {
			return cache.size();
		}

		void clear() {
			cache.clear();
		}

		private void cleanup() {
			long now = System.currentTimeMillis();
			cache.entrySet().removeIf(e -> now - e.getValue().issuedAt >= MAX_TTL_MS);
		}
	}
}
