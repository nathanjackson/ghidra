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

import java.io.IOException;

/**
 * Looks up FIDO2 credential ids the authenticator may assert for a username.
 * Used after the login name is known; the server challenge is not consumed.
 */
@FunctionalInterface
public interface FidoAllowCredentialsLookup {

	/**
	 * {@return credential ids for {@code username}; never null}
	 * @param username login name
	 * @throws IOException if the lookup fails
	 */
	byte[][] getAllowCredentials(String username) throws IOException;
}
