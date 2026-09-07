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

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import javax.security.auth.callback.NameCallback;

import org.junit.After;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.framework.remote.FidoAuthenticationCallback;
import ghidra.util.SystemUtilities;

public class FidoLoginDialogTest extends AbstractGenericTest {

	private static final byte[] CHALLENGE = bytes(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32);
	private static final byte[] CRED_ID = bytes(0xAA, 0xBB, 0xCC);
	private static final byte[] AUTH_DATA = bytes(0x10, 0x11, 0x12);
	private static final byte[] CLIENT_DATA = bytes('{', '}');
	private static final byte[] SIGNATURE = bytes(0x51, 0x52);
	private static final byte[] ATTESTATION = bytes(0xA3, 0x01);

	private FidoLoginDialog dialog;

	@After
	public void tearDown() {
		if (dialog != null) {
			SystemUtilities.runSwingNow(dialog::dispose);
			dialog = null;
		}
	}

	@Test
	public void testOkRunsHelperAndFillsCallback() throws Exception {
		AtomicReference<String> userSeen = new AtomicReference<>();
		StubHelper helper = new StubHelper(false);
		NameCallback nameCb = new NameCallback("User ID:");
		nameCb.setName("alice");
		FidoAuthenticationCallback fidoCb = newCallback();
		dialog = newDialog(nameCb, fidoCb, helper, username -> {
			userSeen.set(username);
			return new byte[][] { CRED_ID };
		});

		SystemUtilities.runSwingNow(() -> {
			assertEquals("alice", dialog.getNameField().getText());
			assertEquals("", dialog.getEnrollTokenField().getText());
			dialog.okCallback();
		});
		dialog.waitForWorker();

		assertTrue(dialog.okWasPressed());
		assertEquals("alice", nameCb.getName());
		assertEquals("alice", userSeen.get());
		assertArrayEquals(CRED_ID, fidoCb.getCredentialId());
		assertArrayEquals(SIGNATURE, fidoCb.getSignature());
		assertNull(fidoCb.getAttestationObject());
		assertNull(fidoCb.getEnrollToken());
		assertEquals(1, helper.calls.get());
	}

	@Test
	public void testEnrollTokenSelectsCreate() throws Exception {
		StubHelper helper = new StubHelper(true);
		NameCallback nameCb = new NameCallback("User ID:");
		nameCb.setName("bob");
		FidoAuthenticationCallback fidoCb = newCallback();
		dialog = newDialog(nameCb, fidoCb, helper, null);

		SystemUtilities.runSwingNow(() -> {
			dialog.getEnrollTokenField().setText(" enroll-token ");
			dialog.okCallback();
		});
		dialog.waitForWorker();

		assertTrue(dialog.okWasPressed());
		assertEquals("create", helper.lastOp.get());
		assertEquals("enroll-token", fidoCb.getEnrollToken());
		assertArrayEquals(ATTESTATION, fidoCb.getAttestationObject());
	}

	@Test
	public void testCancelDoesNotRunHelper() throws Exception {
		StubHelper helper = new StubHelper(false);
		helper.hangUntilCancel = true;
		NameCallback nameCb = new NameCallback("User ID:");
		nameCb.setName("alice");
		dialog = newDialog(nameCb, newCallback(), helper, null);

		SystemUtilities.runSwingNow(dialog::okCallback);
		assertTrue(helper.started.await(5, TimeUnit.SECONDS));
		SystemUtilities.runSwingNow(dialog::cancelCallback);
		dialog.waitForWorker();

		assertFalse(dialog.okWasPressed());
		assertNull(dialog.getFailure());
	}

	@Test
	public void testHelperErrorStaysOpen() throws Exception {
		FidoHelper failing = (json, timeoutMs) -> {
			throw new IOException("touch timeout");
		};
		NameCallback nameCb = new NameCallback("User ID:");
		nameCb.setName("alice");
		FidoAuthenticationCallback fidoCb = newCallback();
		dialog = newDialog(nameCb, fidoCb, failing, null);

		SystemUtilities.runSwingNow(dialog::okCallback);
		dialog.waitForWorker();

		assertFalse(dialog.okWasPressed());
		assertEquals("touch timeout", dialog.getFailure().getMessage());
		assertNull(fidoCb.getCredentialId());
		SystemUtilities.runSwingNow(
			() -> assertEquals("touch timeout", dialog.getStatusText()));
	}

	private FidoLoginDialog newDialog(NameCallback nameCb, FidoAuthenticationCallback fidoCb,
			FidoHelper helper, FidoAllowCredentialsLookup lookup) {
		return SystemUtilities.runSwingNow(
			() -> new FidoLoginDialog(nameCb, fidoCb, "server.example.test",
				new FidoAuthenticator(helper), lookup, null));
	}

	private static FidoAuthenticationCallback newCallback() {
		return new FidoAuthenticationCallback("ghidra.example.org", "Example", CHALLENGE, null,
			false, 60);
	}

	private static class StubHelper implements FidoHelper {
		private final boolean create;
		private final CountDownLatch started = new CountDownLatch(1);
		private final AtomicInteger calls = new AtomicInteger();
		private final AtomicReference<String> lastOp = new AtomicReference<>();
		volatile boolean hangUntilCancel;

		StubHelper(boolean create) {
			this.create = create;
		}

		@Override
		public String execute(String requestJson, int timeoutMs) throws IOException {
			calls.incrementAndGet();
			if (requestJson.contains("\"op\":\"create\"")) {
				lastOp.set("create");
			}
			else {
				lastOp.set("assert");
			}
			started.countDown();
			if (hangUntilCancel) {
				while (!Thread.currentThread().isInterrupted()) {
					try {
						Thread.sleep(50);
					}
					catch (InterruptedException e) {
						Thread.currentThread().interrupt();
						throw new IOException("FIDO authentication cancelled");
					}
				}
				throw new IOException("FIDO authentication cancelled");
			}
			String cred = FidoAuthenticator.encodeBase64Url(CRED_ID);
			String auth = FidoAuthenticator.encodeBase64Url(AUTH_DATA);
			String client = FidoAuthenticator.encodeBase64Url(CLIENT_DATA);
			String sig = FidoAuthenticator.encodeBase64Url(SIGNATURE);
			String att = FidoAuthenticator.encodeBase64Url(ATTESTATION);
			if (create) {
				return "{\"credentialId\":\"" + cred + "\",\"authenticatorData\":\"" + auth +
					"\",\"clientDataJSON\":\"" + client + "\",\"signature\":\"" + sig +
					"\",\"attestationObject\":\"" + att + "\"}";
			}
			return "{\"credentialId\":\"" + cred + "\",\"authenticatorData\":\"" + auth +
				"\",\"clientDataJSON\":\"" + client + "\",\"signature\":\"" + sig + "\"}";
		}
	}
}