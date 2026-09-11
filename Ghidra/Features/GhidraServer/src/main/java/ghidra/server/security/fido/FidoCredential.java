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
package ghidra.server.security.fido;

/**
 * One registered FIDO2 credential stored under {@code ~fido/<username>.json}.
 * Byte fields are encoded as unpadded base64url.
 */
public class FidoCredential {

	private String credentialId;
	private String publicKeyCose;
	private long signCount;
	/**
	 * Authenticator AAGUID. Informational only: not authenticated under
	 * {@code fmt=none} attestation and must not be used for policy.
	 */
	private String aaguid;
	private long createdEpochMs;

	/**
	 * Gson constructor.
	 */
	public FidoCredential() {
		// required for Gson
	}

	/**
	 * Construct a credential record.
	 * @param credentialId unpadded base64url credential id
	 * @param publicKeyCose unpadded base64url COSE_Key bytes
	 * @param signCount authenticator signature counter
	 * @param aaguid optional authenticator AAGUID (string or base64); may be null
	 * @param createdEpochMs creation time in milliseconds since the epoch
	 */
	public FidoCredential(String credentialId, String publicKeyCose, long signCount, String aaguid,
			long createdEpochMs) {
		this.credentialId = credentialId;
		this.publicKeyCose = publicKeyCose;
		this.signCount = signCount;
		this.aaguid = aaguid;
		this.createdEpochMs = createdEpochMs;
	}

	public String getCredentialId() {
		return credentialId;
	}

	public String getPublicKeyCose() {
		return publicKeyCose;
	}

	public long getSignCount() {
		return signCount;
	}

	public String getAaguid() {
		return aaguid;
	}

	public long getCreatedEpochMs() {
		return createdEpochMs;
	}

	/**
	 * {@return a copy of this credential with an updated signature counter}
	 * @param newSignCount replacement signature counter
	 */
	public FidoCredential withSignCount(long newSignCount) {
		return new FidoCredential(credentialId, publicKeyCose, newSignCount, aaguid,
			createdEpochMs);
	}
}
