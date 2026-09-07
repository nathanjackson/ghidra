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
package ghidra.framework.remote;

import java.io.Serializable;
import java.util.Arrays;

import javax.security.auth.callback.Callback;

/**
 * <code>FidoAuthenticationCallback</code> provides a Callback implementation used
 * to perform FIDO2/WebAuthn authentication.  This callback is instantiated
 * by the server with relying-party identity, a random challenge, and either
 * an allow-list of credential ids (assertion/login) or an enroll request
 * (makeCredential).
 * <p>
 * It is the responsibility of the callback handler to invoke
 * {@link #setAssertion(byte[], byte[], byte[], byte[])} and, when enrolling,
 * {@link #setAttestationObject(byte[])}, then return this object in response
 * to the callback.  Enrollment may also require {@link #setEnrollToken(String)}.
 * <p>
 * The supplied challenge is validated by the server during authentication as one
 * that it had issued.  This callback must be completed and returned to the server
 * in a short period of time or the authentication will fail.
 */
public class FidoAuthenticationCallback implements Callback, Serializable {

	public static final long serialVersionUID = 1L;

	private final String rpId;
	private final String rpName;
	private final byte[] challenge;
	private final byte[][] allowCredentials;
	private final boolean enroll;
	private final int timeoutSeconds;

	private String enrollToken;
	private byte[] credentialId;
	private byte[] authenticatorData;
	private byte[] clientDataJSON;
	private byte[] signature;
	private byte[] attestationObject;

	/**
	 * Construct callback with FIDO2 relying-party parameters and a random challenge.
	 * A null or empty {@code allowCredentials} list indicates enrollment
	 * ({@code makeCredential}); otherwise the client should produce an assertion
	 * for one of the listed credential ids.
	 * @param rpId WebAuthn relying-party id (stable hostname)
	 * @param rpName relying-party display name; may be null
	 * @param challenge random bytes to be signed (32 or more)
	 * @param allowCredentials credential ids allowed for assertion; null or empty
	 *        means enroll
	 * @param enroll true to register a new credential; false to assert
	 * @param timeoutSeconds client time budget in seconds
	 */
	public FidoAuthenticationCallback(String rpId, String rpName, byte[] challenge,
			byte[][] allowCredentials, boolean enroll, int timeoutSeconds) {
		this.rpId = rpId;
		this.rpName = rpName;
		this.challenge = copy(challenge);
		this.allowCredentials = copy(allowCredentials);
		this.enroll = enroll;
		this.timeoutSeconds = timeoutSeconds;
	}

	/**
	 * {@return WebAuthn relying-party id}
	 */
	public String getRpId() {
		return rpId;
	}

	/**
	 * {@return relying-party display name; may be null}
	 */
	public String getRpName() {
		return rpName;
	}

	/**
	 * {@return copy of the challenge bytes to be signed}
	 */
	public byte[] getChallenge() {
		return copy(challenge);
	}

	/**
	 * {@return copy of credential ids allowed for assertion, or null if unspecified}
	 */
	public byte[][] getAllowCredentials() {
		return copy(allowCredentials);
	}

	/**
	 * {@return true if this callback is for FIDO2 credential enrollment}
	 */
	public boolean isEnroll() {
		return enroll;
	}

	/**
	 * {@return client time budget in seconds}
	 */
	public int getTimeoutSeconds() {
		return timeoutSeconds;
	}

	/**
	 * Set the one-time admin enrollment token.  Method must be invoked by
	 * the callback handler when {@link #isEnroll()} is true.
	 * @param token one-time admin enrollment code
	 */
	public void setEnrollToken(String token) {
		this.enrollToken = token;
	}

	/**
	 * {@return one-time admin enrollment token set by the callback handler}
	 */
	public String getEnrollToken() {
		return enrollToken;
	}

	/**
	 * Clear the enrollment token so it is not left in memory after use.
	 */
	public void clearEnrollToken() {
		enrollToken = null;
	}

	/**
	 * Set assertion data produced by the authenticator.  Method must be invoked
	 * by the callback handler.
	 * @param credentialId credential id used for the assertion
	 * @param authenticatorData WebAuthn authenticator data
	 * @param clientDataJSON WebAuthn client data JSON
	 * @param signature assertion signature
	 */
	public void setAssertion(byte[] credentialId, byte[] authenticatorData, byte[] clientDataJSON,
			byte[] signature) {
		this.credentialId = copy(credentialId);
		this.authenticatorData = copy(authenticatorData);
		this.clientDataJSON = copy(clientDataJSON);
		this.signature = copy(signature);
	}

	/**
	 * {@return copy of the credential id used for the assertion}
	 */
	public byte[] getCredentialId() {
		return copy(credentialId);
	}

	/**
	 * {@return copy of the WebAuthn authenticator data}
	 */
	public byte[] getAuthenticatorData() {
		return copy(authenticatorData);
	}

	/**
	 * {@return copy of the WebAuthn client data JSON}
	 */
	public byte[] getClientDataJSON() {
		return copy(clientDataJSON);
	}

	/**
	 * {@return copy of the assertion signature}
	 */
	public byte[] getSignature() {
		return copy(signature);
	}

	/**
	 * Set the CBOR attestation object produced during enrollment.
	 * Method must be invoked by the callback handler when {@link #isEnroll()}
	 * is true.
	 * @param attestationObject CBOR attestation object
	 */
	public void setAttestationObject(byte[] attestationObject) {
		this.attestationObject = copy(attestationObject);
	}

	/**
	 * {@return copy of the CBOR attestation object}
	 */
	public byte[] getAttestationObject() {
		return copy(attestationObject);
	}

	/**
	 * Clear assertion fields so they are not left in memory after use.
	 */
	public void clearAssertion() {
		wipe(credentialId);
		credentialId = null;
		wipe(authenticatorData);
		authenticatorData = null;
		wipe(clientDataJSON);
		clientDataJSON = null;
		wipe(signature);
		signature = null;
	}

	/**
	 * Clear the attestation object so it is not left in memory after use.
	 */
	public void clearAttestationObject() {
		wipe(attestationObject);
		attestationObject = null;
	}

	@Override
	public String toString() {
		int credCount = allowCredentials == null ? 0 : allowCredentials.length;
		return "FidoAuthenticationCallback[rpId=" + rpId + ", rpName=" + rpName + ", enroll=" +
			enroll + ", timeoutSeconds=" + timeoutSeconds + ", allowCredentials=" + credCount + "]";
	}

	private static byte[] copy(byte[] src) {
		return src == null ? null : src.clone();
	}

	private static byte[][] copy(byte[][] src) {
		if (src == null) {
			return null;
		}
		byte[][] dest = new byte[src.length][];
		for (int i = 0; i < src.length; i++) {
			dest[i] = copy(src[i]);
		}
		return dest;
	}

	private static void wipe(byte[] data) {
		if (data != null) {
			Arrays.fill(data, (byte) 0);
		}
	}

}
