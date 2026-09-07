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
package ghidra.server;

import static org.junit.Assert.*;

import java.io.*;
import java.util.List;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.server.security.fido.FidoCredential;
import ghidra.server.security.fido.FidoCredentialStore;
import utilities.util.FileUtilities;

public class FidoAdminTest extends AbstractGenericTest {

	private static final String USER = "alice";
	private static final String UNKNOWN = "bob";
	private static final String CRED_ID_1 = "cred-one";
	private static final String CRED_ID_2 = "cred-two";

	private File root;
	private RepositoryManager mgr;

	public FidoAdminTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		root = createTempDirectory(getName());
		writeUsers(root, USER);
	}

	@After
	public void tearDown() {
		if (mgr != null) {
			mgr.dispose();
			mgr = null;
		}
	}

	@Test
	public void testSvrAdminEnrollQueuesHashNotPlaintext() throws Exception {
		ByteArrayOutputStream captured = new ByteArrayOutputStream();
		PrintStream original = System.out;
		System.setOut(new PrintStream(captured, true));
		try {
			new ServerAdmin().execute(new String[] { root.getAbsolutePath(), "-fido-enroll", USER });
		}
		finally {
			System.setOut(original);
		}

		String output = captured.toString();
		assertTrue(output.contains("FIDO enrollment code for user '" + USER + "':"));
		String token = extractEnrollToken(output);
		assertNotNull(token);
		assertTrue(token.length() >= 20);

		File cmdDir = new File(root, "~admin");
		File[] cmdFiles = cmdDir.listFiles(CommandProcessor.CMD_FILE_FILTER);
		assertNotNull(cmdFiles);
		assertEquals(1, cmdFiles.length);
		List<String> lines = FileUtilities.getLines(cmdFiles[0]);
		assertEquals(1, lines.size());
		String cmd = lines.get(0);
		assertTrue(cmd.startsWith(CommandProcessor.FIDO_ENROLL_COMMAND + " " + USER + " "));
		assertFalse(cmd.contains(token));
		String[] parts = cmd.split(" ");
		assertEquals(4, parts.length);
		assertEquals(64, parts[2].length());
		assertEquals(FidoCredentialStore.hashEnrollToken(token), parts[2]);

		mgr = new RepositoryManager(root, false, 0, false);
		FidoCredentialStore store = mgr.getUserManager().getFidoCredentialStore();
		assertTrue(store.hasPendingEnrollToken(USER));
		assertTrue(store.consumeEnrollToken(USER, token));
		assertFalse(store.consumeEnrollToken(USER, token));
	}

	@Test
	public void testUnknownUserEnrollFails() throws Exception {
		assertFalse(UserManager.getUsers(root).contains(UNKNOWN));

		mgr = new RepositoryManager(root, false, 0, false);
		File cmdFile = writeCommand(
			CommandProcessor.FIDO_ENROLL_COMMAND + " " + UNKNOWN + " " +
				FidoCredentialStore.hashEnrollToken("unused-token") + " " +
				(System.currentTimeMillis() + FidoCredentialStore.DEFAULT_ENROLL_TTL_MS));
		CommandProcessor.processCommands(mgr);
		assertFalse(cmdFile.exists());
		assertFalse(mgr.getUserManager().getFidoCredentialStore().hasPendingEnrollToken(UNKNOWN));
		File enrollFile = new File(new File(root, FidoCredentialStore.FIDO_DIR_NAME),
			UNKNOWN + FidoCredentialStore.ENROLL_FILE_EXT);
		assertFalse(enrollFile.exists());
	}

	@Test
	public void testRevokeOneVersusAllViaCommandProcessor() throws Exception {
		mgr = new RepositoryManager(root, false, 0, false);
		FidoCredentialStore store = mgr.getUserManager().getFidoCredentialStore();
		store.addCredential(USER, new FidoCredential(CRED_ID_1, "cose-1", 0L, "aa", 1L));
		store.addCredential(USER, new FidoCredential(CRED_ID_2, "cose-2", 0L, "bb", 2L));
		store.issueEnrollTokenHash(USER, FidoCredentialStore.hashEnrollToken("pending"),
			System.currentTimeMillis() + FidoCredentialStore.DEFAULT_ENROLL_TTL_MS);

		writeCommand(CommandProcessor.FIDO_REVOKE_COMMAND + " " + USER + " " + CRED_ID_1);
		CommandProcessor.processCommands(mgr);
		List<FidoCredential> remaining = store.loadCredentials(USER);
		assertEquals(1, remaining.size());
		assertEquals(CRED_ID_2, remaining.get(0).getCredentialId());
		assertTrue(store.hasPendingEnrollToken(USER));

		writeCommand(CommandProcessor.FIDO_REVOKE_COMMAND + " " + USER);
		CommandProcessor.processCommands(mgr);
		assertTrue(store.loadCredentials(USER).isEmpty());
		assertFalse(store.hasPendingEnrollToken(USER));
	}

	@Test
	public void testRemoveUserDeletesFidoSidecar() throws Exception {
		mgr = new RepositoryManager(root, false, 0, false);
		FidoCredentialStore store = mgr.getUserManager().getFidoCredentialStore();
		store.addCredential(USER, new FidoCredential(CRED_ID_1, "cose-1", 1L, null, 1L));
		store.issueEnrollTokenHash(USER, FidoCredentialStore.hashEnrollToken("pending"),
			System.currentTimeMillis() + FidoCredentialStore.DEFAULT_ENROLL_TTL_MS);

		File fidoDir = new File(root, FidoCredentialStore.FIDO_DIR_NAME);
		File jsonFile = new File(fidoDir, USER + FidoCredentialStore.CREDENTIAL_FILE_EXT);
		File enrollFile = new File(fidoDir, USER + FidoCredentialStore.ENROLL_FILE_EXT);
		assertTrue(jsonFile.isFile());
		assertTrue(enrollFile.isFile());

		assertTrue(mgr.getUserManager().removeUser(USER));
		assertFalse(jsonFile.exists());
		assertFalse(enrollFile.exists());
		assertFalse(mgr.getUserManager().isValidUser(USER));
	}

	@Test
	public void testRevokeCredentialIdStartingWithDash() throws Exception {
		String dashId = "-abcDEFghij0123456789-_";
		FidoCredentialStore prep = new FidoCredentialStore(root);
		prep.addCredential(USER, new FidoCredential(dashId, "cose-1", 0L, null, 1L));
		prep.addCredential(USER, new FidoCredential(CRED_ID_2, "cose-2", 0L, null, 2L));

		new ServerAdmin().execute(
			new String[] { root.getAbsolutePath(), "-fido-revoke", USER, dashId });

		File cmdDir = new File(root, "~admin");
		File[] cmdFiles = cmdDir.listFiles(CommandProcessor.CMD_FILE_FILTER);
		assertNotNull(cmdFiles);
		assertEquals(1, cmdFiles.length);
		List<String> lines = FileUtilities.getLines(cmdFiles[0]);
		assertEquals(1, lines.size());
		assertEquals(CommandProcessor.FIDO_REVOKE_COMMAND + " " + USER + " " + dashId, lines.get(0));

		mgr = new RepositoryManager(root, false, 0, false);
		FidoCredentialStore store = mgr.getUserManager().getFidoCredentialStore();
		List<FidoCredential> remaining = store.loadCredentials(USER);
		assertEquals(1, remaining.size());
		assertEquals(CRED_ID_2, remaining.get(0).getCredentialId());
	}

	@Test
	public void testRemoveUserRetryDeletesOrphanSidecar() throws Exception {
		mgr = new RepositoryManager(root, false, 0, false);
		FidoCredentialStore store = mgr.getUserManager().getFidoCredentialStore();
		store.addCredential(USER, new FidoCredential(CRED_ID_1, "cose-1", 1L, null, 1L));
		assertTrue(mgr.getUserManager().removeUser(USER));
		assertFalse(mgr.getUserManager().isValidUser(USER));

		store.addCredential(USER, new FidoCredential(CRED_ID_1, "cose-1", 1L, null, 1L));
		File jsonFile = new File(new File(root, FidoCredentialStore.FIDO_DIR_NAME),
			USER + FidoCredentialStore.CREDENTIAL_FILE_EXT);
		assertTrue(jsonFile.isFile());

		assertFalse(mgr.getUserManager().removeUser(USER));
		assertFalse(jsonFile.exists());
	}

	@Test
	public void testInvalidRevokeDoesNotAbortQueue() throws Exception {
		mgr = new RepositoryManager(root, false, 0, false);
		String hash = FidoCredentialStore.hashEnrollToken("queued-token");
		long expiry = System.currentTimeMillis() + FidoCredentialStore.DEFAULT_ENROLL_TTL_MS;
		File cmdDir = CommandProcessor.getOrCreateCommandDir(root);
		CommandProcessor.writeCommands(List.of(
			CommandProcessor.FIDO_REVOKE_COMMAND + " ../etc",
			CommandProcessor.FIDO_ENROLL_COMMAND + " " + USER + " " + hash + " " + expiry),
			cmdDir);
		CommandProcessor.processCommands(mgr);
		assertTrue(mgr.getUserManager().getFidoCredentialStore().hasPendingEnrollToken(USER));
	}

	@Test
	public void testMalformedEnrollHashDoesNotWrite() throws Exception {
		mgr = new RepositoryManager(root, false, 0, false);
		writeCommand(CommandProcessor.FIDO_ENROLL_COMMAND + " " + USER + " not-a-hash " +
			(System.currentTimeMillis() + FidoCredentialStore.DEFAULT_ENROLL_TTL_MS));
		CommandProcessor.processCommands(mgr);
		assertFalse(mgr.getUserManager().getFidoCredentialStore().hasPendingEnrollToken(USER));
	}

	@Test
	public void testFidoListPrintsCredentialsAndPendingEnroll() throws Exception {
		FidoCredentialStore store = new FidoCredentialStore(root);
		store.addCredential(USER,
			new FidoCredential(CRED_ID_1, "cose-1", 4L, "aaguid-1", 1_234L));
		store.issueEnrollTokenHash(USER, FidoCredentialStore.hashEnrollToken("pending"),
			System.currentTimeMillis() + FidoCredentialStore.DEFAULT_ENROLL_TTL_MS);

		ByteArrayOutputStream captured = new ByteArrayOutputStream();
		PrintStream original = System.out;
		System.setOut(new PrintStream(captured, true));
		try {
			new ServerAdmin().execute(new String[] { root.getAbsolutePath(), "-fido-list", USER });
		}
		finally {
			System.setOut(original);
		}

		String output = captured.toString();
		assertTrue(output.contains("FIDO credentials for user '" + USER + "':"));
		assertTrue(output.contains("credentialId=" + CRED_ID_1));
		assertTrue(output.contains("aaguid=aaguid-1"));
		assertTrue(output.contains("createdEpochMs=1234"));
		assertTrue(output.contains("signCount=4"));
		assertTrue(output.contains("enroll token: pending"));
	}

	private static void writeUsers(File serverRoot, String... users) throws IOException {
		StringBuilder buf = new StringBuilder();
		for (String user : users) {
			buf.append(user).append(":*:*\n");
		}
		FileUtilities.writeStringToFile(new File(serverRoot, UserManager.USER_PASSWORD_FILE),
			buf.toString());
	}

	private File writeCommand(String command) throws IOException {
		File cmdDir = CommandProcessor.getOrCreateCommandDir(root);
		CommandProcessor.writeCommands(List.of(command), cmdDir);
		File[] files = cmdDir.listFiles(CommandProcessor.CMD_FILE_FILTER);
		assertNotNull(files);
		assertTrue(files.length >= 1);
		return files[0];
	}

	private static String extractEnrollToken(String output) {
		String marker = "FIDO enrollment code for user '" + USER + "':";
		int ix = output.indexOf(marker);
		if (ix < 0) {
			return null;
		}
		int lineStart = output.indexOf('\n', ix);
		if (lineStart < 0) {
			return null;
		}
		int lineEnd = output.indexOf('\n', lineStart + 1);
		String line = lineEnd < 0 ? output.substring(lineStart + 1)
				: output.substring(lineStart + 1, lineEnd);
		return line.trim();
	}
}
