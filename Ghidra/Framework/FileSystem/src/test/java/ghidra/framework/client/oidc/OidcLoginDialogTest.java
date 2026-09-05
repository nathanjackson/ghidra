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
package ghidra.framework.client.oidc;

import static org.junit.Assert.*;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.After;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.framework.client.oidc.OidcDeviceCodeFlow.DeviceAuthorization;
import ghidra.framework.remote.AnonymousCallback;
import ghidra.framework.remote.OidcAuthenticationCallback;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.CancelledException;

public class OidcLoginDialogTest extends AbstractGenericTest {

	private static final String USER_CODE = "ABCD-EFGH";
	private static final String DEVICE_CODE = "secret-device-code-xyz";
	private static final String ID_TOKEN = "secret.id.token.xyz";
	private static final String VERIFICATION_URI = "https://login.example.test/device";
	private static final String VERIFICATION_URI_COMPLETE =
		"https://login.example.test/device?user_code=ABCD-EFGH";

	private OidcLoginDialog dialog;
	private StubFlow flow;

	@After
	public void tearDown() {
		if (dialog != null) {
			SystemUtilities.runSwingNow(dialog::dispose);
			dialog = null;
		}
	}

	@Test
	public void testConstructionShowsUserCodeAndDoesNotOpenBrowser() throws Exception {
		flow = new StubFlow(authorization(VERIFICATION_URI_COMPLETE));
		flow.hangUntilCancel = true;
		List<URI> opened = new ArrayList<>();
		dialog = newDialog(null, opened::add);

		SystemUtilities.runSwingNow(dialog::startAuthorization);
		assertTrue(flow.started.await(5, TimeUnit.SECONDS));

		SystemUtilities.runSwingNow(() -> {
			assertEquals(USER_CODE, dialog.getUserCodeField().getText());
			assertFalse(dialog.getUserCodeField().isEditable());
			assertTrue(dialog.getUserCodeField().getFont().getSize() >= 18);
			assertEquals(VERIFICATION_URI, dialog.getVerificationUriField().getText());
			assertTrue(dialog.getOpenBrowserButton().isEnabled());
			assertEquals("Waiting for authorization...", dialog.getStatusText());
			assertNull(dialog.getAnonymousCheckBox());
		});
		assertTrue(opened.isEmpty());

		SystemUtilities.runSwingNow(dialog::cancelCallback);
		dialog.waitForWorker();
	}

	@Test
	public void testOpenBrowserUsesCompleteUriAndStaysEnabled() throws Exception {
		flow = new StubFlow(authorization(VERIFICATION_URI_COMPLETE));
		flow.hangUntilCancel = true;
		List<URI> opened = new ArrayList<>();
		dialog = newDialog(null, opened::add);

		SystemUtilities.runSwingNow(dialog::startAuthorization);
		assertTrue(flow.started.await(5, TimeUnit.SECONDS));

		SystemUtilities.runSwingNow(() -> dialog.getOpenBrowserButton().doClick());
		assertEquals(1, opened.size());
		assertEquals(VERIFICATION_URI_COMPLETE, opened.get(0).toString());
		SystemUtilities.runSwingNow(
			() -> assertTrue(dialog.getOpenBrowserButton().isEnabled()));

		SystemUtilities.runSwingNow(dialog::cancelCallback);
		dialog.waitForWorker();
	}

	@Test
	public void testOpenBrowserFallsBackToVerificationUri() throws Exception {
		flow = new StubFlow(authorization(null));
		flow.hangUntilCancel = true;
		List<URI> opened = new ArrayList<>();
		dialog = newDialog(null, opened::add);

		SystemUtilities.runSwingNow(dialog::startAuthorization);
		assertTrue(flow.started.await(5, TimeUnit.SECONDS));

		SystemUtilities.runSwingNow(() -> dialog.getOpenBrowserButton().doClick());
		assertEquals(VERIFICATION_URI, opened.get(0).toString());

		SystemUtilities.runSwingNow(dialog::cancelCallback);
		dialog.waitForWorker();
	}

	@Test
	public void testAnonymousSkipDoesNotStartDeviceFlow() throws Exception {
		flow = new StubFlow(authorization(VERIFICATION_URI_COMPLETE));
		dialog = newDialog(new AnonymousCallback(), uri -> fail("browser should not open"));

		SystemUtilities.runSwingNow(() -> {
			assertNotNull(dialog.getAnonymousCheckBox());
			dialog.getAnonymousCheckBox().setSelected(true);
			dialog.startAuthorization();
		});
		dialog.waitForWorker();

		assertEquals(0, flow.completeCalls.get());
		assertTrue(dialog.anonymousAccessRequested());
		assertFalse(dialog.okWasPressed());
		assertNull(dialog.getIdToken());
		assertNull(dialog.getFailure());
	}

	@Test
	public void testAnonymousSkipCancelsInFlightPoll() throws Exception {
		flow = new StubFlow(authorization(VERIFICATION_URI_COMPLETE));
		flow.hangUntilCancel = true;
		dialog = newDialog(new AnonymousCallback(), uri -> fail("browser should not open"));

		SystemUtilities.runSwingNow(dialog::startAuthorization);
		assertTrue(flow.started.await(5, TimeUnit.SECONDS));
		assertEquals(1, flow.completeCalls.get());

		SystemUtilities.runSwingNow(() -> dialog.getAnonymousCheckBox().setSelected(true));
		dialog.waitForWorker();

		assertTrue(dialog.anonymousAccessRequested());
		assertFalse(dialog.okWasPressed());
		assertNull(dialog.getIdToken());
	}

	@Test
	public void testCancelStopsPolling() throws Exception {
		flow = new StubFlow(authorization(VERIFICATION_URI_COMPLETE));
		flow.hangUntilCancel = true;
		dialog = newDialog(null, uri -> fail("browser should not open"));

		SystemUtilities.runSwingNow(dialog::startAuthorization);
		assertTrue(flow.started.await(5, TimeUnit.SECONDS));

		SystemUtilities.runSwingNow(dialog::cancelCallback);
		dialog.waitForWorker();

		assertFalse(dialog.okWasPressed());
		assertFalse(dialog.anonymousAccessRequested());
		assertNull(dialog.getIdToken());
		assertNull(dialog.getFailure());
	}

	@Test
	public void testSecondStartDoesNotIssueAnotherDeviceCode() throws Exception {
		flow = new StubFlow(authorization(VERIFICATION_URI_COMPLETE));
		flow.hangUntilCancel = true;
		dialog = newDialog(null, uri -> {
			// unused
		});

		SystemUtilities.runSwingNow(() -> {
			dialog.startAuthorization();
			dialog.startAuthorization();
		});
		assertTrue(flow.started.await(5, TimeUnit.SECONDS));
		assertEquals(1, flow.completeCalls.get());

		SystemUtilities.runSwingNow(dialog::cancelCallback);
		dialog.waitForWorker();
	}

	@Test
	public void testSuccessfulPollReturnsIdToken() throws Exception {
		flow = new StubFlow(authorization(VERIFICATION_URI_COMPLETE));
		flow.token = ID_TOKEN;
		dialog = newDialog(null, uri -> fail("browser should not open"));

		SystemUtilities.runSwingNow(dialog::startAuthorization);
		dialog.waitForWorker();

		assertTrue(dialog.okWasPressed());
		assertEquals(ID_TOKEN, dialog.getIdToken());
		assertFalse(dialog.anonymousAccessRequested());
		assertNull(dialog.getFailure());
	}

	private OidcLoginDialog newDialog(AnonymousCallback anonymous, OidcLoginDialog.BrowserOpener opener) {
		return SystemUtilities.runSwingNow(() -> new OidcLoginDialog(newCallback(), anonymous,
			"server.example.test", flow, opener));
	}

	private static DeviceAuthorization authorization(String verificationUriComplete) {
		return new DeviceAuthorization(DEVICE_CODE, USER_CODE, VERIFICATION_URI,
			verificationUriComplete, 1800, 5);
	}

	private static OidcAuthenticationCallback newCallback() {
		return new OidcAuthenticationCallback("https://idp.example.test", "ghidra-client",
			"https://idp.example.test/device", "https://idp.example.test/token", "openid", "nonce",
			"challenge", 30, "Example");
	}

	private static class StubFlow extends OidcDeviceCodeFlow {
		private final DeviceAuthorization auth;
		private final CountDownLatch started = new CountDownLatch(1);
		private final AtomicInteger completeCalls = new AtomicInteger();
		private volatile boolean hangUntilCancel;
		private volatile String token = ID_TOKEN;

		StubFlow(DeviceAuthorization auth) {
			super(HttpClient.newBuilder()
					.followRedirects(HttpClient.Redirect.NEVER)
					.connectTimeout(Duration.ofSeconds(1))
					.build());
			this.auth = auth;
		}

		@Override
		public String complete(OidcAuthenticationCallback oidcCb,
				DeviceAuthorizationListener listener, Cancelled extraCancelled)
				throws IOException, CancelledException {
			completeCalls.incrementAndGet();
			if (listener != null) {
				listener.deviceAuthorizationStarted(auth);
			}
			started.countDown();
			if (hangUntilCancel) {
				while (true) {
					if (extraCancelled != null && extraCancelled.isCancelled()) {
						throw new CancelledException("OIDC authorization cancelled");
					}
					try {
						Thread.sleep(50);
					}
					catch (InterruptedException e) {
						Thread.currentThread().interrupt();
						throw new CancelledException("OIDC authorization cancelled");
					}
				}
			}
			return token;
		}
	}
}
