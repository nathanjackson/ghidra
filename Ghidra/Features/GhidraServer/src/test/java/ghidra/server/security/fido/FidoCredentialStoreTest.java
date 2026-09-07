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

import static org.junit.Assert.*;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.attribute.PosixFilePermission;
import java.util.List;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import utilities.util.FileUtilities;

public class FidoCredentialStoreTest extends AbstractGenericTest {

	private static final String USER = "alice";
	private static final String CRED_ID_1 = "cred-id-one";
	private static final String CRED_ID_2 = "cred-id-two";
	private static final String COSE_1 = "cose-key-one";
	private static final String COSE_2 = "cose-key-two";
	private static final String AAGUID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

	private File root;
	private FidoCredentialStore store;

	public FidoCredentialStoreTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		root = createTempDirectory(getName());
		store = new FidoCredentialStore(root);
	}

	@Test
	public void testJsonRoundTrip() throws Exception {
		long created = 1_700_000_000_000L;
		FidoCredential original = new FidoCredential(CRED_ID_1, COSE_1, 7L, AAGUID, created);
		store.addCredential(USER, original);

		File jsonFile = new File(new File(root, FidoCredentialStore.FIDO_DIR_NAME),
			USER + FidoCredentialStore.CREDENTIAL_FILE_EXT);
		assertTrue(jsonFile.isFile());
		String json = FileUtilities.getText(jsonFile);
		assertTrue(json.contains("\"credentialId\":"));
		assertTrue(json.contains(CRED_ID_1));
		assertTrue(json.contains("\"publicKeyCose\":"));
		assertTrue(json.contains(COSE_1));
		assertTrue(json.contains("\"signCount\":"));
		assertTrue(json.contains("\"aaguid\":"));
		assertTrue(json.contains(AAGUID));
		assertTrue(json.contains("\"createdEpochMs\":"));

		List<FidoCredential> loaded = store.loadCredentials(USER);
		assertEquals(1, loaded.size());
		FidoCredential copy = loaded.get(0);
		assertEquals(CRED_ID_1, copy.getCredentialId());
		assertEquals(COSE_1, copy.getPublicKeyCose());
		assertEquals(7L, copy.getSignCount());
		assertEquals(AAGUID, copy.getAaguid());
		assertEquals(created, copy.getCreatedEpochMs());
	}

	@Test
	public void testAddReplaceAndUpdateSignCount() throws Exception {
		store.addCredential(USER, new FidoCredential(CRED_ID_1, COSE_1, 0L, null, 1L));
		store.addCredential(USER, new FidoCredential(CRED_ID_2, COSE_2, 0L, AAGUID, 2L));
		assertEquals(2, store.loadCredentials(USER).size());

		store.addCredential(USER, new FidoCredential(CRED_ID_1, "cose-replaced", 3L, "ag", 1L));
		List<FidoCredential> loaded = store.loadCredentials(USER);
		assertEquals(2, loaded.size());
		assertEquals("cose-replaced", loaded.get(0).getPublicKeyCose());
		assertEquals(3L, loaded.get(0).getSignCount());

		assertTrue(store.updateSignCount(USER, CRED_ID_2, 11L));
		assertEquals(11L, store.loadCredentials(USER).get(1).getSignCount());
		assertFalse(store.updateSignCount(USER, "missing", 1L));
	}

	@Test
	public void testConsumeEnrollTokenOnceRejectsReplay() throws Exception {
		String token = FidoCredentialStore.generateEnrollToken();
		assertTrue(token.length() >= 20);
		assertTrue(token.matches("[A-Za-z0-9_-]+"));

		String hash = FidoCredentialStore.hashEnrollToken(token);
		assertEquals(64, hash.length());
		store.issueEnrollTokenHash(USER, hash,
			System.currentTimeMillis() + FidoCredentialStore.DEFAULT_ENROLL_TTL_MS);

		assertTrue(store.hasPendingEnrollToken(USER));
		assertTrue(store.consumeEnrollToken(USER, token));
		assertFalse(store.hasPendingEnrollToken(USER));
		assertFalse(store.consumeEnrollToken(USER, token));
	}

	@Test
	public void testMatchesEnrollTokenDoesNotConsume() throws Exception {
		String token = FidoCredentialStore.generateEnrollToken();
		store.issueEnrollTokenHash(USER, FidoCredentialStore.hashEnrollToken(token),
			System.currentTimeMillis() + FidoCredentialStore.DEFAULT_ENROLL_TTL_MS);

		assertTrue(store.matchesEnrollToken(USER, token));
		assertTrue(store.hasPendingEnrollToken(USER));
		assertFalse(store.matchesEnrollToken(USER, "not-the-token"));
		assertTrue(store.hasPendingEnrollToken(USER));
		assertTrue(store.consumeEnrollToken(USER, token));
		assertFalse(store.matchesEnrollToken(USER, token));
	}

	@Test
	public void testWrongEnrollTokenDoesNotConsume() throws Exception {
		String token = FidoCredentialStore.generateEnrollToken();
		store.issueEnrollTokenHash(USER, FidoCredentialStore.hashEnrollToken(token),
			System.currentTimeMillis() + FidoCredentialStore.DEFAULT_ENROLL_TTL_MS);

		assertFalse(store.consumeEnrollToken(USER, "not-the-token"));
		assertTrue(store.hasPendingEnrollToken(USER));
		assertTrue(store.consumeEnrollToken(USER, token));
	}

	@Test
	public void testExpiredEnrollTokenRejected() throws Exception {
		String token = FidoCredentialStore.generateEnrollToken();
		store.issueEnrollTokenHash(USER, FidoCredentialStore.hashEnrollToken(token),
			System.currentTimeMillis() - 1L);

		assertFalse(store.hasPendingEnrollToken(USER));
		assertFalse(store.consumeEnrollToken(USER, token));
		File enrollFile = new File(new File(root, FidoCredentialStore.FIDO_DIR_NAME),
			USER + FidoCredentialStore.ENROLL_FILE_EXT);
		assertFalse(enrollFile.exists());
	}

	@Test
	public void testRevokeOneVersusAll() throws Exception {
		store.addCredential(USER, new FidoCredential(CRED_ID_1, COSE_1, 0L, null, 1L));
		store.addCredential(USER, new FidoCredential(CRED_ID_2, COSE_2, 0L, null, 2L));
		String token = FidoCredentialStore.generateEnrollToken();
		store.issueEnrollTokenHash(USER, FidoCredentialStore.hashEnrollToken(token),
			System.currentTimeMillis() + FidoCredentialStore.DEFAULT_ENROLL_TTL_MS);

		assertTrue(store.removeCredential(USER, CRED_ID_1));
		List<FidoCredential> remaining = store.loadCredentials(USER);
		assertEquals(1, remaining.size());
		assertEquals(CRED_ID_2, remaining.get(0).getCredentialId());
		assertTrue(store.hasPendingEnrollToken(USER));
		assertFalse(store.removeCredential(USER, CRED_ID_1));

		store.removeAll(USER);
		assertTrue(store.loadCredentials(USER).isEmpty());
		assertFalse(store.hasPendingEnrollToken(USER));
		File fidoDir = new File(root, FidoCredentialStore.FIDO_DIR_NAME);
		assertFalse(new File(fidoDir, USER + FidoCredentialStore.CREDENTIAL_FILE_EXT).exists());
		assertFalse(new File(fidoDir, USER + FidoCredentialStore.ENROLL_FILE_EXT).exists());
	}

	@Test
	public void testInvalidUsernameRejected() {
		try {
			store.loadCredentials("../etc/passwd");
			fail("expected IllegalArgumentException");
		}
		catch (IllegalArgumentException e) {
			// expected
		}
		catch (Exception e) {
			fail("expected IllegalArgumentException, got " + e);
		}
	}

	@Test
	public void testMissingUserLoadsEmpty() throws Exception {
		assertTrue(store.loadCredentials("nobody").isEmpty());
		assertFalse(store.hasPendingEnrollToken("nobody"));
		assertFalse(store.consumeEnrollToken("nobody", "x"));
	}

	@Test
	public void testFidoDirOwnerOnlyPermissions() throws Exception {
		File fidoDir = new File(root, FidoCredentialStore.FIDO_DIR_NAME);
		assertTrue(fidoDir.isDirectory());
		Set<PosixFilePermission> perms = Files.getPosixFilePermissions(fidoDir.toPath());
		assertTrue(perms.contains(PosixFilePermission.OWNER_READ));
		assertTrue(perms.contains(PosixFilePermission.OWNER_WRITE));
		assertTrue(perms.contains(PosixFilePermission.OWNER_EXECUTE));
		assertFalse(perms.contains(PosixFilePermission.GROUP_READ));
		assertFalse(perms.contains(PosixFilePermission.GROUP_WRITE));
		assertFalse(perms.contains(PosixFilePermission.GROUP_EXECUTE));
		assertFalse(perms.contains(PosixFilePermission.OTHERS_READ));
		assertFalse(perms.contains(PosixFilePermission.OTHERS_WRITE));
		assertFalse(perms.contains(PosixFilePermission.OTHERS_EXECUTE));
	}

	@Test
	public void testExistingFidoDirIsChmoddedOwnerOnly() throws Exception {
		File fidoDir = new File(root, FidoCredentialStore.FIDO_DIR_NAME);
		assertTrue(fidoDir.setReadable(true, false));
		assertTrue(fidoDir.setWritable(true, false));
		assertTrue(fidoDir.setExecutable(true, false));

		FidoCredentialStore again = new FidoCredentialStore(root);
		again.loadCredentials(USER);

		Set<PosixFilePermission> perms = Files.getPosixFilePermissions(fidoDir.toPath());
		assertFalse(perms.contains(PosixFilePermission.GROUP_READ));
		assertFalse(perms.contains(PosixFilePermission.OTHERS_READ));
		assertFalse(perms.contains(PosixFilePermission.GROUP_EXECUTE));
		assertFalse(perms.contains(PosixFilePermission.OTHERS_EXECUTE));
	}

	@Test
	public void testMalformedHashRejected() throws Exception {
		try {
			store.issueEnrollTokenHash(USER, "not-a-hash",
				System.currentTimeMillis() + FidoCredentialStore.DEFAULT_ENROLL_TTL_MS);
			fail("expected IllegalArgumentException");
		}
		catch (IllegalArgumentException e) {
			assertTrue(e.getMessage().contains("64 hex"));
		}
		assertFalse(store.hasPendingEnrollToken(USER));
		assertNull(FidoCredentialStore.decodeTokenHash("xyz"));
		assertNull(FidoCredentialStore.decodeTokenHash(""));
		byte[] digest = FidoCredentialStore.decodeTokenHash(
			FidoCredentialStore.hashEnrollToken("token"));
		assertNotNull(digest);
		assertEquals(32, digest.length);
	}
}
