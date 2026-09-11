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

import java.util.Locale;

/**
 * Client-side WebAuthn relying-party id helpers. Mirrors server
 * {@code FidoAssertionVerifier} normalization so FileSystem does not depend
 * on GhidraServer packages. The client binds callback {@code rpId} to the
 * host it actually connected to before invoking {@code ghidra-fido}.
 */
public final class FidoRpId {

	public static final String MISMATCH_MESSAGE = "Relying party ID does not match server host";

	private FidoRpId() {
		// utility
	}

	/**
	 * Lowercase ASCII rpId. Rejects scheme, port, and path. {@code ::1} /
	 * {@code [::1]} are allowed loopback literals.
	 * @param rpId candidate relying-party id
	 * @return normalized rpId
	 */
	public static String normalize(String rpId) {
		if (rpId == null || rpId.isBlank()) {
			throw new IllegalArgumentException("rpId is required");
		}
		String n = rpId.trim().toLowerCase(Locale.ROOT);
		if (n.contains("://") || n.indexOf('/') >= 0 || n.indexOf(' ') >= 0) {
			throw new IllegalArgumentException("rpId must be a hostname or loopback literal");
		}
		int colon = n.indexOf(':');
		if (colon > 0 && n.indexOf(':', colon + 1) < 0) {
			throw new IllegalArgumentException("rpId must be a hostname or loopback literal");
		}
		return n;
	}

	/**
	 * {@return true if {@code rpId} is a loopback literal}
	 */
	public static boolean isLoopback(String rpId) {
		if (rpId == null) {
			return false;
		}
		String n = rpId.trim().toLowerCase(Locale.ROOT);
		return "localhost".equals(n) || "127.0.0.1".equals(n) || "::1".equals(n) ||
			"[::1]".equals(n);
	}

	/**
	 * {@return true if callback rpId is the connected host, or both are loopback}
	 * <p>
	 * Malformed values fail closed (false), they do not throw.
	 */
	public static boolean matchesConnectedHost(String rpId, String connectedHost) {
		if (rpId == null || connectedHost == null) {
			return false;
		}
		try {
			String a = normalize(rpId);
			String b = normalize(connectedHost);
			if (a.equals(b)) {
				return true;
			}
			return isLoopback(a) && isLoopback(b);
		}
		catch (IllegalArgumentException e) {
			return false;
		}
	}

	/**
	 * {@return WebAuthn origin for {@code rpId}}
	 */
	public static String originFor(String rpId) {
		if (rpId == null) {
			return "https://localhost";
		}
		String n = rpId.trim().toLowerCase(Locale.ROOT);
		if (isLoopback(n)) {
			if ("127.0.0.1".equals(n)) {
				return "http://127.0.0.1";
			}
			if ("::1".equals(n) || "[::1]".equals(n)) {
				return "http://[::1]";
			}
			return "http://localhost";
		}
		return "https://" + n;
	}
}
