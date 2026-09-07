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

import java.io.File;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.login.FailedLoginException;

import org.junit.*;
import org.junit.experimental.categories.Category;

import generic.test.category.PortSensitiveCategory;
import ghidra.framework.client.fido.FidoAuthenticator;
import ghidra.framework.client.fido.FidoHelper;
import ghidra.framework.model.ServerInfo;
import ghidra.framework.remote.RemoteRepositoryServerHandle;
import ghidra.net.DefaultKeyManagerFactory;
import ghidra.server.remote.ServerTestUtil;
import ghidra.server.security.fido.FidoCredentialStore;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;

/**
 * Slow IntegrationTest: Ghidra Server {@code -a5} FIDO2 login through
 * {@link ServerConnectTask} using a mock authenticator (no YubiKey).
 */
@Category(PortSensitiveCategory.class)
public class GhidraServerFidoConnectTest extends AbstractGhidraHeadlessIntegrationTest {

	private static final String USER = "test";
	private static final int AUTH_MODE_FIDO = 5;

	private File serverRoot;

	@Before
	public void setUp() throws Exception {
		System.clearProperty(DefaultKeyManagerFactory.KEYSTORE_PATH_PROPERTY);
	}

	@After
	public void tearDown() throws Exception {
		closeAllWindows();
		killServer();
		ClientUtil.setClientAuthenticator(new PasswordClientAuthenticator("unused"));
		ClientUtil.clearRepositoryAdapter("localhost", ServerTestUtil.GHIDRA_TEST_SERVER_PORT);
	}

	@Test
	public void testEnrollLoginAndNegativeCases() throws Exception {
		startFidoServer();
		MockEs256FidoHelper helper = new MockEs256FidoHelper();

		installAuthenticator(helper, null);
		assertConnectFails();

		installAuthenticator(helper, "not-issued-token");
		assertConnectFails();

		String token = issueEnrollToken(USER);
		installAuthenticator(helper, token);
		RemoteRepositoryServerHandle enrolled = connect();
		assertEquals(USER, enrolled.getUser());
		assertFalse(enrolled.isReadOnly());

		installAuthenticator(helper, null);
		RemoteRepositoryServerHandle loggedIn = connect();
		assertEquals(USER, loggedIn.getUser());
		assertFalse(loggedIn.isReadOnly());

		helper.rotateKey();
		installAuthenticator(helper, null);
		assertConnectFails();
	}

	private void startFidoServer() throws Exception {
		serverRoot = new File(getTestDirectoryPath(), "FidoTestServer");
		FileUtilities.deleteDir(serverRoot);
		FileUtilities.mkdirs(serverRoot);
		ServerTestUtil.createUsers(serverRoot.getAbsolutePath(), USER);
		ServerTestUtil.setLocalUser(USER);
		ServerTestUtil.startServer(serverRoot.getAbsolutePath(),
			ServerTestUtil.GHIDRA_TEST_SERVER_PORT, AUTH_MODE_FIDO, false, false, false);
	}

	private String issueEnrollToken(String username) throws Exception {
		String token = FidoCredentialStore.generateEnrollToken();
		FidoCredentialStore store = new FidoCredentialStore(serverRoot);
		store.issueEnrollTokenHash(username, FidoCredentialStore.hashEnrollToken(token),
			System.currentTimeMillis() + FidoCredentialStore.DEFAULT_ENROLL_TTL_MS);
		return token;
	}

	private void installAuthenticator(FidoHelper helper, String enrollToken) {
		Map<String, String> env = new HashMap<>();
		if (enrollToken != null) {
			env.put(HeadlessClientAuthenticator.FIDO_ENROLL_TOKEN_ENV, enrollToken);
		}
		FidoAuthenticator authenticator = new FidoAuthenticator(helper);
		ClientUtil.setClientAuthenticator(
			new HeadlessClientAuthenticator(authenticator, env::get));
	}

	private RemoteRepositoryServerHandle connect() throws Exception {
		ServerConnectTask task = new ServerConnectTask(
			new ServerInfo("localhost", ServerTestUtil.GHIDRA_TEST_SERVER_PORT), false);
		task.run(TaskMonitor.DUMMY);
		if (task.getException() != null) {
			throw new AssertionError("FIDO server connect failed", task.getException());
		}
		RemoteRepositoryServerHandle handle = task.getRepositoryServerHandle();
		assertNotNull("ServerConnectTask should return a repository handle", handle);
		return handle;
	}

	private void assertConnectFails() {
		ServerConnectTask task = new ServerConnectTask(
			new ServerInfo("localhost", ServerTestUtil.GHIDRA_TEST_SERVER_PORT), false);
		try {
			task.run(TaskMonitor.DUMMY);
		}
		catch (CancelledException e) {
			fail("connect should not be cancelled");
		}
		assertNull(task.getRepositoryServerHandle());
		Exception e = task.getException();
		assertNotNull(e);
		assertTrue("expected FailedLoginException, got " + e.getClass().getName() + ": " + e,
			e instanceof FailedLoginException);
	}

	private void killServer() {
		if (serverRoot == null) {
			return;
		}
		ServerTestUtil.disposeServer();
		FileUtilities.deleteDir(serverRoot);
		serverRoot = null;
	}
}
