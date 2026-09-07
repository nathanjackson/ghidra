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

import java.io.IOException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import ghidra.framework.remote.FidoAuthenticationCallback;
import ghidra.framework.remote.GhidraPrincipal;
import ghidra.server.UserManager;
import ghidra.server.security.fido.FidoAssertionVerifier;
import ghidra.server.security.fido.FidoAssertionVerifier.Enrollment;
import ghidra.server.security.fido.FidoAssertionVerifier.VerificationException;
import ghidra.server.security.fido.FidoCredential;
import ghidra.server.security.fido.FidoCredentialStore;

/**
 * FIDO2/WebAuthn authentication module for {@code -a5}.
 * <p>
 * Callbacks are a {@link NameCallback} plus a {@link FidoAuthenticationCallback} with
 * an empty allow-list. Clients that need per-user allowCredentials should call
 * {@link #getAllowCredentials(UserManager, String, byte[])} (exposed remotely as
 * {@code GhidraServerHandle.getFidoAllowCredentials}) after the user id is known,
 * passing the still-valid callback challenge. A live challenge plus an enrolled
 * username discloses that user's credential ids; unknown, unenrolled, invalid, and
 * unauthenticated callers all receive an empty array.
 * Enrollment is selected by a one-time admin enroll token on the callback, not by
 * the server-issued {@code enroll} flag (always false for the one-round callback).
 */
public class FidoAuthenticationModule implements AuthenticationModule {

	static final Logger log = LogManager.getLogger(FidoAuthenticationModule.class);

	public static final String DEFAULT_RP_NAME = "Ghidra Server";
	public static final int DEFAULT_TIMEOUT_SECONDS = 60;
	public static final String RMI_SERVER_PROPERTY = "java.rmi.server.hostname";

	private static final String AUTH_FAILED = "Authentication failed";
	private static final byte[][] EMPTY_ALLOW = new byte[0][];

	private final String rpId;
	private final String rpName;
	private final int timeoutSeconds;
	private final FidoAssertionVerifier verifier;

	/**
	 * Construct using {@link #resolveDefaultRpId()}.
	 */
	public FidoAuthenticationModule() {
		this(resolveDefaultRpId());
	}

	/**
	 * Construct with an explicit relying-party id (tests inject this).
	 * @param rpId WebAuthn relying-party id
	 */
	public FidoAuthenticationModule(String rpId) {
		this(rpId, DEFAULT_RP_NAME, DEFAULT_TIMEOUT_SECONDS);
	}

	/**
	 * @param rpId WebAuthn relying-party id
	 * @param rpName relying-party display name
	 * @param timeoutSeconds client time budget in seconds
	 */
	public FidoAuthenticationModule(String rpId, String rpName, int timeoutSeconds) {
		this.rpId = FidoAssertionVerifier.normalizeRpId(rpId);
		this.rpName = rpName;
		this.timeoutSeconds = timeoutSeconds;
		this.verifier = new FidoAssertionVerifier(this.rpId);
	}

	/**
	 * RP ID defaults to {@code java.rmi.server.hostname} (set by {@code -ip}) when present,
	 * otherwise {@code localhost} (suitable for tests; production should pass {@code -ip}).
	 * @return relying-party id
	 */
	public static String resolveDefaultRpId() {
		String hostname = System.getProperty(RMI_SERVER_PROPERTY);
		if (hostname != null) {
			hostname = hostname.trim();
			if (!hostname.isEmpty()) {
				return FidoAssertionVerifier.normalizeRpId(hostname);
			}
		}
		return "localhost";
	}

	/**
	 * {@return the configured relying-party id}
	 */
	public String getRpId() {
		return rpId;
	}

	@Override
	public boolean anonymousCallbacksAllowed() {
		return false;
	}

	@Override
	public boolean isNameCallbackAllowed() {
		return true;
	}

	@Override
	public Callback[] getAuthenticationCallbacks() {
		byte[] challenge = TokenGenerator.getNewToken();
		FidoAuthenticationCallback fidoCb = new FidoAuthenticationCallback(rpId, rpName, challenge,
			EMPTY_ALLOW, false, timeoutSeconds);
		NameCallback nameCb = new NameCallback(USERNAME_CALLBACK_PROMPT + ":");
		return new Callback[] { nameCb, fidoCb };
	}

	/**
	 * Credential ids registered for {@code username}. Requires a still-valid
	 * (unconsumed) login challenge from {@link #getAuthenticationCallbacks()}.
	 * Unknown users, users with no credentials, invalid input, I/O errors, and
	 * a missing/stale challenge all return an empty array. Given a live challenge,
	 * an enrolled username is distinguishable from an unknown one because ids
	 * are returned.
	 * @param userMgr server user manager
	 * @param username login name
	 * @param challenge callback challenge bytes (not consumed)
	 * @return copies of credential id bytes; never null
	 */
	public byte[][] getAllowCredentials(UserManager userMgr, String username, byte[] challenge) {
		try {
			if (!TokenGenerator.hasIssuedToken(challenge)) {
				return EMPTY_ALLOW;
			}
			if (userMgr == null || username == null || !UserManager.isValidUserName(username)) {
				return EMPTY_ALLOW;
			}
			List<FidoCredential> list =
				userMgr.getFidoCredentialStore().loadCredentials(username);
			List<byte[]> ids = new ArrayList<>();
			for (FidoCredential credential : list) {
				byte[] id = decodeBase64Url(credential.getCredentialId());
				if (id != null && id.length > 0) {
					ids.add(id);
				}
			}
			return ids.toArray(new byte[0][]);
		}
		catch (IOException | RuntimeException e) {
			log.warn("FIDO allowCredentials lookup failed: {}", e.getMessage());
			return EMPTY_ALLOW;
		}
	}

	@Override
	public String authenticate(UserManager userMgr, Subject subject, Callback[] callbacks)
			throws LoginException {
		GhidraPrincipal user = GhidraPrincipal.getGhidraPrincipal(subject);
		if (user == null) {
			throw new FailedLoginException("GhidraPrincipal required");
		}
		String username = user.getName();
		NameCallback nameCb =
			AuthenticationModule.getFirstCallbackOfType(NameCallback.class, callbacks);
		if (nameCb != null && !StringUtils.isBlank(nameCb.getName())) {
			username = nameCb.getName();
		}
		if (StringUtils.isBlank(username)) {
			throw new FailedLoginException("User ID must be specified");
		}

		FidoAuthenticationCallback fidoCb =
			AuthenticationModule.getFirstCallbackOfType(FidoAuthenticationCallback.class,
				callbacks);
		if (fidoCb == null) {
			throw new FailedLoginException("FIDO authentication callback required");
		}

		byte[] challenge = fidoCb.getChallenge();
		byte[] credentialId = fidoCb.getCredentialId();
		byte[] authenticatorData = fidoCb.getAuthenticatorData();
		byte[] clientDataJSON = fidoCb.getClientDataJSON();
		byte[] signature = fidoCb.getSignature();
		byte[] attestationObject = fidoCb.getAttestationObject();
		String enrollToken = fidoCb.getEnrollToken();
		boolean enroll = fidoCb.isEnroll() || !StringUtils.isBlank(enrollToken);

		fidoCb.clearEnrollToken();
		fidoCb.clearAssertion();
		fidoCb.clearAttestationObject();

		if (!TokenGenerator.isValidToken(challenge)) {
			fail(username, "invalid or stale challenge");
		}
		if (!UserManager.isValidUserName(username)) {
			fail(username, "invalid username");
		}
		if (userMgr == null) {
			fail(username, "user manager required");
		}

		try {
			if (enroll) {
				return enroll(userMgr, username, enrollToken, challenge, authenticatorData,
					clientDataJSON, attestationObject);
			}
			return assertLogin(userMgr, username, challenge, credentialId, authenticatorData,
				clientDataJSON, signature);
		}
		catch (FailedLoginException e) {
			throw e;
		}
		catch (VerificationException e) {
			fail(username, e.getMessage());
		}
		catch (IOException | RuntimeException e) {
			fail(username, e.getMessage() == null ? e.toString() : e.getMessage());
		}
		catch (StackOverflowError e) {
			fail(username, "verification overflow");
		}
		throw new FailedLoginException(AUTH_FAILED);
	}

	private String enroll(UserManager userMgr, String username, String enrollToken,
			byte[] challenge, byte[] authenticatorData, byte[] clientDataJSON,
			byte[] attestationObject) throws FailedLoginException, VerificationException,
			IOException {
		if (StringUtils.isBlank(enrollToken)) {
			fail(username, "enroll token required");
		}
		FidoCredentialStore store = userMgr.getFidoCredentialStore();
		if (!store.matchesEnrollToken(username, enrollToken)) {
			fail(username, "enroll token invalid or already used");
		}
		Enrollment enrollment = verifier.verifyAttestation(challenge, authenticatorData,
			clientDataJSON, attestationObject);
		if (!store.consumeEnrollToken(username, enrollToken)) {
			fail(username, "enroll token invalid or already used");
		}
		FidoCredential credential = new FidoCredential(encodeBase64Url(enrollment.getCredentialId()),
			encodeBase64Url(enrollment.getPublicKeyCose()), enrollment.getSignCount(),
			encodeBase64Url(enrollment.getAaguid()), System.currentTimeMillis());
		store.addCredential(username, credential);
		return username;
	}

	private String assertLogin(UserManager userMgr, String username, byte[] challenge,
			byte[] credentialId, byte[] authenticatorData, byte[] clientDataJSON, byte[] signature)
			throws FailedLoginException, VerificationException, IOException {
		if (credentialId == null || credentialId.length == 0) {
			fail(username, "credential id required");
		}
		FidoCredentialStore store = userMgr.getFidoCredentialStore();
		List<FidoCredential> credentials = store.loadCredentials(username);
		FidoCredential match = findCredential(credentials, credentialId);
		if (match == null) {
			fail(username, credentials.isEmpty() ? "no credential" : "unknown credential");
		}
		byte[] publicKeyCose = decodeBase64Url(match.getPublicKeyCose());
		if (publicKeyCose == null) {
			fail(username, "stored COSE key invalid");
		}
		long newCount = verifier.verifyAssertion(challenge, authenticatorData, clientDataJSON,
			signature, publicKeyCose, match.getSignCount());
		if (!store.updateSignCount(username, match.getCredentialId(), newCount)) {
			fail(username, "failed to persist signCount");
		}
		return username;
	}

	private static FidoCredential findCredential(List<FidoCredential> credentials,
			byte[] credentialId) {
		for (FidoCredential credential : credentials) {
			byte[] stored = decodeBase64Url(credential.getCredentialId());
			if (stored != null && MessageDigest.isEqual(stored, credentialId)) {
				return credential;
			}
		}
		return null;
	}

	private static void fail(String username, String reason) throws FailedLoginException {
		log.warn("FIDO authentication failed for user '{}': {}", username, reason);
		throw new FailedLoginException(AUTH_FAILED);
	}

	static String encodeBase64Url(byte[] data) {
		if (data == null) {
			return null;
		}
		return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
	}

	static byte[] decodeBase64Url(String data) {
		if (data == null || data.isBlank()) {
			return null;
		}
		try {
			return Base64.getUrlDecoder().decode(data);
		}
		catch (IllegalArgumentException e) {
			return null;
		}
	}
}
