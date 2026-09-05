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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

import javax.security.auth.login.LoginException;

import com.nimbusds.jwt.JWTClaimsSet;

import generic.hash.HashUtilities;
import ghidra.server.UserManager;
import ghidra.util.NumericUtilities;

/**
 * Maps verified ID-token claims to a Ghidra user name.
 */
public final class OidcUsernameMapper {

	public static final int MAX_USERNAME_LENGTH = 64;
	private static final String TENANT_ID_CLAIM = "tid";
	private static final String HOSTED_DOMAIN_CLAIM = "hd";

	private final String usernameClaim;
	private final List<String> usernameClaimFallbacks;
	private final String tenantId;
	private final String hostedDomain;

	public OidcUsernameMapper(String usernameClaim, List<String> usernameClaimFallbacks,
			String tenantId, String hostedDomain) {
		if (usernameClaim == null || usernameClaim.isBlank()) {
			throw new IllegalArgumentException("usernameClaim is required");
		}
		this.usernameClaim = usernameClaim;
		this.usernameClaimFallbacks = usernameClaimFallbacks == null ? List.of()
				: List.copyOf(usernameClaimFallbacks);
		this.tenantId = blankToNull(tenantId);
		this.hostedDomain = blankToNull(hostedDomain);
	}

	public OidcUsernameMapper(OidcConfig config) {
		this(config.getUsernameClaim(), config.getUsernameClaimFallbacks(), config.getTenantId(),
			config.getHostedDomain());
	}

	/**
	 * Map verified claims to a Ghidra user name that passes
	 * {@link UserManager#isValidUserName(String)}.
	 *
	 * @param claims verified ID-token claims
	 * @return Ghidra user name
	 * @throws LoginException if tenant/domain constraints fail or no valid name can be produced
	 */
	public String map(JWTClaimsSet claims) throws LoginException {
		if (claims == null) {
			throw new LoginException("ID token claims are required");
		}
		verifyOptionalClaim(claims, TENANT_ID_CLAIM, tenantId);
		verifyOptionalClaim(claims, HOSTED_DOMAIN_CLAIM, hostedDomain);

		for (String claimName : claimNames()) {
			String sanitized = sanitize(stringClaim(claims, claimName));
			if (isValidMappedName(sanitized)) {
				return sanitized;
			}
		}

		String hashed = hashSubject(claims.getSubject());
		if (isValidMappedName(hashed)) {
			return hashed;
		}
		throw new LoginException("Unable to map ID token to a Ghidra user name");
	}

	/**
	 * Lowercase, take the email local-part, strip invalid characters, and cap length.
	 *
	 * @param raw claim value
	 * @return sanitized name, or {@code null} if nothing usable remains
	 */
	public static String sanitize(String raw) {
		if (raw == null) {
			return null;
		}
		String value = raw.trim().toLowerCase(Locale.ROOT);
		if (value.isEmpty()) {
			return null;
		}
		int at = value.indexOf('@');
		if (at >= 0) {
			value = value.substring(0, at);
		}
		StringBuilder buf = new StringBuilder();
		for (int i = 0; i < value.length(); i++) {
			char c = value.charAt(i);
			if (!isAllowedCharacter(c, buf.length() == 0)) {
				continue;
			}
			buf.append(c);
			if (buf.length() >= MAX_USERNAME_LENGTH) {
				break;
			}
		}
		return buf.length() == 0 ? null : buf.toString();
	}

	static String hashSubject(String subject) {
		if (subject == null || subject.isEmpty()) {
			return null;
		}
		try {
			MessageDigest digest = MessageDigest.getInstance(HashUtilities.SHA256_ALGORITHM);
			byte[] hash = digest.digest(subject.getBytes(StandardCharsets.UTF_8));
			String hex = Objects.requireNonNull(NumericUtilities.convertBytesToString(hash));
			return "u" + hex.substring(0, 16);
		}
		catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("SHA-256 not available", e);
		}
	}

	private List<String> claimNames() {
		List<String> names = new ArrayList<>();
		names.add(usernameClaim);
		for (String fallback : usernameClaimFallbacks) {
			if (!names.contains(fallback)) {
				names.add(fallback);
			}
		}
		return names;
	}

	private static void verifyOptionalClaim(JWTClaimsSet claims, String claimName, String expected)
			throws LoginException {
		if (expected == null) {
			return;
		}
		String actual = stringClaim(claims, claimName);
		if (actual == null || !expected.equals(actual)) {
			throw new LoginException("Authentication failed");
		}
	}

	private static String stringClaim(JWTClaimsSet claims, String claimName) {
		if (claimName == null || claimName.isBlank()) {
			return null;
		}
		try {
			return claims.getStringClaim(claimName);
		}
		catch (ParseException e) {
			return null;
		}
	}

	private static boolean isValidMappedName(String name) {
		return name != null && name.length() <= MAX_USERNAME_LENGTH &&
			UserManager.isValidUserName(name);
	}

	private static boolean isAllowedCharacter(char c, boolean first) {
		boolean alphanumeric = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
		if (first) {
			return alphanumeric;
		}
		return alphanumeric || c == '.' || c == '-' || c == '_';
	}

	private static String blankToNull(String value) {
		if (value == null) {
			return null;
		}
		String trimmed = value.trim();
		return trimmed.isEmpty() ? null : trimmed;
	}
}
