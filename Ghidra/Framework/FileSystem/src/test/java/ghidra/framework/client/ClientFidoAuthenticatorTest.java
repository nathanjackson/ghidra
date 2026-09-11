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
package ghidra.framework.client;

import static org.junit.Assert.*;

import java.rmi.RemoteException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.login.FailedLoginException;

import org.junit.After;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.framework.remote.FidoAuthenticationCallback;
import ghidra.framework.remote.GhidraServerHandle;
import ghidra.framework.remote.RemoteRepositoryServerHandle;

public class ClientFidoAuthenticatorTest extends AbstractGenericTest {

	private static final byte[] CHALLENGE = bytes(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32);
	private static final byte[] CRED_ID = bytes(0xAA, 0xBB, 0xCC);
	private static final byte[] AUTH_DATA = bytes(0x10, 0x11, 0x12);
	private static final byte[] CLIENT_DATA = bytes('{', '}');
	private static final byte[] SIGNATURE = bytes(0x51, 0x52);

	@After
	public void tearDown() {
		ClientUtil.setClientAuthenticator(new PasswordClientAuthenticator("unused"));
	}

	@Test
	public void testPasswordAuthenticatorReturnsFalse() throws Exception {
		PasswordClientAuthenticator auth = new PasswordClientAuthenticator("unused");
		FidoAuthenticationCallback fido = newCallback();
		assertFalse(auth.processFidoCallback(null, fido, "server.example.test"));
		assertNull(fido.getCredentialId());
	}

	@Test
	public void testClientUtilSetsAssertionViaAuthenticator() throws Exception {
		RecordingAuthenticator recording = new RecordingAuthenticator(true);
		ClientUtil.setClientAuthenticator(recording);
		NameCallback nameCb = new NameCallback("User ID:");
		FidoAuthenticationCallback fido = newCallback();
		FakeHandle handle = new FakeHandle(new byte[][] { CRED_ID });

		assertTrue(ClientUtil.processFidoCallback(new Callback[] { nameCb, fido },
			"server.example.test", "alice", handle, null));
		assertEquals("alice", nameCb.getName());
		assertArrayEquals(CRED_ID, fido.getCredentialId());
		assertArrayEquals(SIGNATURE, fido.getSignature());
		assertTrue(recording.called.get());
	}

	@Test
	public void testClientUtilCancelReturnsFalse() throws Exception {
		ClientUtil.setClientAuthenticator(new RecordingAuthenticator(false));
		FidoAuthenticationCallback fido = newCallback();
		assertFalse(ClientUtil.processFidoCallback(new Callback[] { fido }, "server.example.test",
			"alice", null, null));
		assertNull(fido.getCredentialId());
	}

	@Test
	public void testClientUtilLooksUpAllowCredentials() throws Exception {
		AtomicReference<String> lookedUp = new AtomicReference<>();
		RecordingAuthenticator recording = new RecordingAuthenticator(true);
		ClientUtil.setClientAuthenticator(recording);
		NameCallback nameCb = new NameCallback("User ID:");
		FidoAuthenticationCallback fido = newCallback();
		FakeHandle handle = new FakeHandle(new byte[][] { CRED_ID }) {
			@Override
			public byte[][] getFidoAllowCredentials(String username, byte[] challenge)
					throws RemoteException {
				lookedUp.set(username);
				assertArrayEquals(CHALLENGE, challenge);
				return super.getFidoAllowCredentials(username, challenge);
			}
		};

		assertTrue(ClientUtil.processFidoCallback(new Callback[] { nameCb, fido },
			"server.example.test", "alice", handle, null));
		// Custom authenticators do not receive the allow-list lookup; Default and
		// Headless do (see HeadlessClientAuthenticatorFidoTest).
		assertNull(lookedUp.get());
		assertTrue(recording.called.get());
	}

	private static FidoAuthenticationCallback newCallback() {
		return new FidoAuthenticationCallback("ghidra.example.org", "Example", CHALLENGE, null,
			false, 60);
	}

	private static class RecordingAuthenticator extends PasswordClientAuthenticator {
		private final AtomicBoolean called = new AtomicBoolean();
		private final boolean result;

		RecordingAuthenticator(boolean result) {
			super("unused");
			this.result = result;
		}

		@Override
		public boolean processFidoCallback(NameCallback nameCb, FidoAuthenticationCallback fidoCb,
				String serverName) {
			called.set(true);
			if (result) {
				fidoCb.setAssertion(CRED_ID, AUTH_DATA, CLIENT_DATA, SIGNATURE);
			}
			return result;
		}
	}

	static class FakeHandle implements GhidraServerHandle {
		private final byte[][] allow;

		FakeHandle(byte[][] allow) {
			this.allow = allow;
		}

		@Override
		public Callback[] getAuthenticationCallbacks() {
			return new Callback[0];
		}

		@Override
		public byte[][] getFidoAllowCredentials(String username, byte[] challenge)
				throws RemoteException {
			return allow;
		}

		@Override
		public RemoteRepositoryServerHandle getRepositoryServer(Subject user,
				Callback[] authCallbacks) throws FailedLoginException, RemoteException {
			return null;
		}

		@Override
		public void checkCompatibility(int clientInterfaceVersion) {
			// unused
		}
	}
}
