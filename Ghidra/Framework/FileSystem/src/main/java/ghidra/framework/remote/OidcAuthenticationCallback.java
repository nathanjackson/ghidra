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

import javax.security.auth.callback.Callback;

/**
 * <code>OidcAuthenticationCallback</code> provides a Callback implementation used
 * to perform OIDC authentication via the device-code grant.  This callback is
 * instantiated by the server with the OIDC provider metadata needed for the
 * client to complete a device-code login, plus a one-time login challenge and
 * nonce.
 * <p>
 * It is the responsibility of the callback handler to obtain an ID token from
 * the token endpoint and invoke {@link #setIdToken(String)} before returning
 * this object in response to the callback.
 * <p>
 * This callback must be completed and returned to the server before
 * {@link #getLoginTimeoutSeconds()} elapses or the authentication will fail.
 */
public class OidcAuthenticationCallback implements Callback, Serializable {

	public static final long serialVersionUID = 1L;

	private final String issuer;
	private final String clientId;
	private final String deviceAuthorizationEndpoint;
	private final String tokenEndpoint;
	private final String scopes;
	private final String nonce;
	private final String loginChallenge;
	private final int loginTimeoutSeconds;
	private final String displayName;

	private String idToken;

	/**
	 * Construct callback with OIDC device-code metadata for the client.
	 * @param issuer OIDC issuer identifier
	 * @param clientId OAuth client identifier registered at the issuer
	 * @param deviceAuthorizationEndpoint device authorization endpoint URL
	 * @param tokenEndpoint token endpoint URL
	 * @param scopes space-delimited OAuth scopes to request
	 * @param nonce nonce the client must present in the ID token
	 * @param loginChallenge one-time login challenge issued by the server
	 * @param loginTimeoutSeconds seconds allowed to complete authentication
	 * @param displayName display name of the identity provider
	 */
	public OidcAuthenticationCallback(String issuer, String clientId,
			String deviceAuthorizationEndpoint, String tokenEndpoint, String scopes, String nonce,
			String loginChallenge, int loginTimeoutSeconds, String displayName) {
		this.issuer = issuer;
		this.clientId = clientId;
		this.deviceAuthorizationEndpoint = deviceAuthorizationEndpoint;
		this.tokenEndpoint = tokenEndpoint;
		this.scopes = scopes;
		this.nonce = nonce;
		this.loginChallenge = loginChallenge;
		this.loginTimeoutSeconds = loginTimeoutSeconds;
		this.displayName = displayName;
	}

	/**
	 * {@return OIDC issuer identifier}
	 */
	public String getIssuer() {
		return issuer;
	}

	/**
	 * {@return OAuth client identifier registered at the issuer}
	 */
	public String getClientId() {
		return clientId;
	}

	/**
	 * {@return device authorization endpoint URL}
	 */
	public String getDeviceAuthorizationEndpoint() {
		return deviceAuthorizationEndpoint;
	}

	/**
	 * {@return token endpoint URL}
	 */
	public String getTokenEndpoint() {
		return tokenEndpoint;
	}

	/**
	 * {@return space-delimited OAuth scopes to request}
	 */
	public String getScopes() {
		return scopes;
	}

	/**
	 * {@return nonce the client must present in the ID token}
	 */
	public String getNonce() {
		return nonce;
	}

	/**
	 * {@return one-time login challenge issued by the server}
	 */
	public String getLoginChallenge() {
		return loginChallenge;
	}

	/**
	 * {@return seconds allowed to complete authentication}
	 */
	public int getLoginTimeoutSeconds() {
		return loginTimeoutSeconds;
	}

	/**
	 * {@return display name of the identity provider}
	 */
	public String getDisplayName() {
		return displayName;
	}

	/**
	 * {@return ID token set by the callback handler, or null if not set}
	 */
	public String getIdToken() {
		return idToken;
	}

	/**
	 * Set the ID token obtained from the token endpoint.  Method must be
	 * invoked by the callback handler.
	 * @param idToken ID token
	 */
	public void setIdToken(String idToken) {
		this.idToken = idToken;
	}

	/**
	 * Clear the ID token from this callback.
	 */
	public void clearIdToken() {
		idToken = null;
	}

	@Override
	public String toString() {
		StringBuffer buf = new StringBuffer();
		buf.append("OidcAuthenticationCallback[issuer=");
		buf.append(issuer);
		buf.append(", clientId=");
		buf.append(clientId);
		buf.append(", deviceAuthorizationEndpoint=");
		buf.append(deviceAuthorizationEndpoint);
		buf.append(", tokenEndpoint=");
		buf.append(tokenEndpoint);
		buf.append(", scopes=");
		buf.append(scopes);
		buf.append(", loginTimeoutSeconds=");
		buf.append(loginTimeoutSeconds);
		buf.append(", displayName=");
		buf.append(displayName);
		buf.append("]");
		return buf.toString();
	}

}
