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
import java.io.IOException;
import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.util.List;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.login.FailedLoginException;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.framework.remote.FidoAuthenticationCallback;
import ghidra.framework.remote.GhidraPrincipal;
import ghidra.server.RepositoryManager;
import ghidra.server.UserManager;
import ghidra.server.security.AuthenticationModule;
import ghidra.server.security.FidoAuthenticationModule;
import utilities.util.FileUtilities;

public class FidoAuthenticationModuleTest extends AbstractGenericTest {

	private static final String USER = "alice";
	private static final String OTHER = "bob";
	private static final String RP_ID = "localhost";
	private static final String ORIGIN = "https://localhost";

	private File root;
	private RepositoryManager mgr;
	private FidoAuthenticationModule module;
	private KeyPair es256;
	private byte[] cose;
	private byte[] credId;

	public FidoAuthenticationModuleTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		root = createTempDirectory(getName());
		writeUsers(root, USER);
		mgr = new RepositoryManager(root, false, 0, false);
		module = new FidoAuthenticationModule(RP_ID);
		es256 = FidoWebAuthnFixtures.es256();
		cose = FidoWebAuthnFixtures.coseEs256((ECPublicKey) es256.getPublic());
		credId = FidoWebAuthnFixtures.CRED_ID;
	}

	@After
	public void tearDown() {
		if (mgr != null) {
			mgr.dispose();
			mgr = null;
		}
	}

	@Test
	public void testCallbacksIncludeNameAndEmptyAllowList() {
		assertTrue(module.isNameCallbackAllowed());
		assertFalse(module.anonymousCallbacksAllowed());
		Callback[] callbacks = module.getAuthenticationCallbacks();
		assertEquals(2, callbacks.length);
		NameCallback nameCb =
			AuthenticationModule.getFirstCallbackOfType(NameCallback.class, callbacks);
		FidoAuthenticationCallback fidoCb =
			AuthenticationModule.getFirstCallbackOfType(FidoAuthenticationCallback.class,
				callbacks);
		assertNotNull(nameCb);
		assertNotNull(fidoCb);
		assertEquals(RP_ID, fidoCb.getRpId());
		assertFalse(fidoCb.isEnroll());
		assertEquals(0, fidoCb.getAllowCredentials().length);
		assertEquals(64, fidoCb.getChallenge().length);
		assertEquals(FidoAuthenticationModule.DEFAULT_TIMEOUT_SECONDS, fidoCb.getTimeoutSeconds());
	}

	@Test
	public void testAssertionSuccessAndSignCountUpdate() throws Exception {
		storeCredential(0);
		Callback[] callbacks = module.getAuthenticationCallbacks();
		fillName(callbacks, USER);
		fillAssertion(callbacks, 1);

		String username = module.authenticate(userMgr(), subject(USER), callbacks);
		assertEquals(USER, username);

		List<FidoCredential> loaded = store().loadCredentials(USER);
		assertEquals(1, loaded.size());
		assertEquals(1L, loaded.get(0).getSignCount());
	}

	@Test
	public void testWrongChallenge() throws Exception {
		storeCredential(0);
		Callback[] callbacks = module.getAuthenticationCallbacks();
		fillName(callbacks, USER);
		FidoAuthenticationCallback fidoCb = fido(callbacks);
		byte[] other = fidoCb.getChallenge().clone();
		other[0] ^= 0x5A;
		byte[] authData = FidoWebAuthnFixtures.authenticatorData(RP_ID,
			FidoAssertionVerifier.FLAG_UP | FidoAssertionVerifier.FLAG_UV, 1);
		byte[] clientData =
			FidoWebAuthnFixtures.clientDataJSON("webauthn.get", other, ORIGIN);
		byte[] signature =
			FidoWebAuthnFixtures.signEs256(es256.getPrivate(), authData, clientData);
		fidoCb.setAssertion(credId, authData, clientData, signature);

		assertAuthFailed(callbacks);
	}

	@Test
	public void testStaleChallengeReplay() throws Exception {
		storeCredential(0);
		Callback[] callbacks = module.getAuthenticationCallbacks();
		fillName(callbacks, USER);
		fillAssertion(callbacks, 1);
		FidoAuthenticationCallback replayCb = copyAssertion(callbacks);
		assertEquals(USER, module.authenticate(userMgr(), subject(USER), callbacks));

		assertAuthFailed(new Callback[] { name(USER), replayCb });
	}

	@Test
	public void testUvMissing() throws Exception {
		storeCredential(0);
		Callback[] callbacks = module.getAuthenticationCallbacks();
		fillName(callbacks, USER);
		FidoAuthenticationCallback fidoCb = fido(callbacks);
		byte[] authData = FidoWebAuthnFixtures.authenticatorData(RP_ID,
			FidoAssertionVerifier.FLAG_UP, 1);
		byte[] clientData =
			FidoWebAuthnFixtures.clientDataJSON("webauthn.get", fidoCb.getChallenge(), ORIGIN);
		byte[] signature =
			FidoWebAuthnFixtures.signEs256(es256.getPrivate(), authData, clientData);
		fidoCb.setAssertion(credId, authData, clientData, signature);

		assertAuthFailed(callbacks);
	}

	@Test
	public void testSignCountDecrease() throws Exception {
		storeCredential(5);
		Callback[] callbacks = module.getAuthenticationCallbacks();
		fillName(callbacks, USER);
		fillAssertion(callbacks, 4);
		assertAuthFailed(callbacks);
	}

	@Test
	public void testUnknownUser() throws Exception {
		Callback[] callbacks = module.getAuthenticationCallbacks();
		fillName(callbacks, OTHER);
		fillAssertion(callbacks, 1);
		assertAuthFailed(callbacks);
	}

	@Test
	public void testNoCredential() throws Exception {
		Callback[] callbacks = module.getAuthenticationCallbacks();
		fillName(callbacks, USER);
		fillAssertion(callbacks, 1);
		assertAuthFailed(callbacks);
	}

	@Test
	public void testEnrollNoneAttestation() throws Exception {
		String token = issueEnrollToken();
		Callback[] callbacks = module.getAuthenticationCallbacks();
		fillName(callbacks, USER);
		fillEnroll(callbacks, token, 0);

		assertEquals(USER, module.authenticate(userMgr(), subject(USER), callbacks));

		List<FidoCredential> loaded = store().loadCredentials(USER);
		assertEquals(1, loaded.size());
		assertEquals(FidoWebAuthnFixtures.b64(credId), loaded.get(0).getCredentialId());
		assertEquals(FidoWebAuthnFixtures.b64(cose), loaded.get(0).getPublicKeyCose());
		assertFalse(store().hasPendingEnrollToken(USER));
	}

	@Test
	public void testEnrollTokenRequired() throws Exception {
		Callback[] issued = module.getAuthenticationCallbacks();
		FidoAuthenticationCallback src = fido(issued);
		int flags = FidoAssertionVerifier.FLAG_UP | FidoAssertionVerifier.FLAG_UV |
			FidoAssertionVerifier.FLAG_AT;
		byte[] authData =
			FidoWebAuthnFixtures.authenticatorData(RP_ID, flags, 0, credId, cose);
		byte[] clientData = FidoWebAuthnFixtures.clientDataJSON("webauthn.create",
			src.getChallenge(), ORIGIN);
		FidoAuthenticationCallback enrollCb = new FidoAuthenticationCallback(src.getRpId(),
			src.getRpName(), src.getChallenge(), src.getAllowCredentials(), true,
			src.getTimeoutSeconds());
		enrollCb.setAssertion(credId, authData, clientData, new byte[] { 1 });
		enrollCb.setAttestationObject(FidoWebAuthnFixtures.attestationNone(authData));

		assertAuthFailed(new Callback[] { name(USER), enrollCb });
	}

	@Test
	public void testEnrollTokenReplay() throws Exception {
		String token = issueEnrollToken();
		Callback[] first = module.getAuthenticationCallbacks();
		fillName(first, USER);
		fillEnroll(first, token, 0);
		assertEquals(USER, module.authenticate(userMgr(), subject(USER), first));

		Callback[] second = module.getAuthenticationCallbacks();
		fillName(second, USER);
		fillEnroll(second, token, 1);
		assertAuthFailed(second);
	}

	@Test
	public void testGetAllowCredentialsEmptyForUnknown() throws Exception {
		byte[][] ids = module.getAllowCredentials(userMgr(), OTHER);
		assertNotNull(ids);
		assertEquals(0, ids.length);
		assertEquals(0, module.getAllowCredentials(userMgr(), "not a user!").length);
		assertEquals(0, module.getAllowCredentials(userMgr(), null).length);
	}

	@Test
	public void testGetAllowCredentialsReturnsStoredIds() throws Exception {
		storeCredential(0);
		byte[][] ids = module.getAllowCredentials(userMgr(), USER);
		assertEquals(1, ids.length);
		assertArrayEquals(credId, ids[0]);
	}

	@Test
	public void testNameCallbackOverridesPrincipal() throws Exception {
		storeCredential(0);
		Callback[] callbacks = module.getAuthenticationCallbacks();
		fillName(callbacks, USER);
		fillAssertion(callbacks, 1);
		assertEquals(USER, module.authenticate(userMgr(), subject("osuser"), callbacks));
	}

	private void storeCredential(long signCount) throws IOException {
		store().addCredential(USER, new FidoCredential(FidoWebAuthnFixtures.b64(credId),
			FidoWebAuthnFixtures.b64(cose), signCount, FidoWebAuthnFixtures.b64(
				FidoWebAuthnFixtures.AAGUID),
			1L));
	}

	private String issueEnrollToken() throws IOException {
		String token = FidoCredentialStore.generateEnrollToken();
		store().issueEnrollTokenHash(USER, FidoCredentialStore.hashEnrollToken(token),
			System.currentTimeMillis() + FidoCredentialStore.DEFAULT_ENROLL_TTL_MS);
		return token;
	}

	private void fillAssertion(Callback[] callbacks, long signCount) throws Exception {
		FidoAuthenticationCallback fidoCb = fido(callbacks);
		byte[] authData = FidoWebAuthnFixtures.authenticatorData(RP_ID,
			FidoAssertionVerifier.FLAG_UP | FidoAssertionVerifier.FLAG_UV, signCount);
		byte[] clientData =
			FidoWebAuthnFixtures.clientDataJSON("webauthn.get", fidoCb.getChallenge(), ORIGIN);
		byte[] signature =
			FidoWebAuthnFixtures.signEs256(es256.getPrivate(), authData, clientData);
		fidoCb.setAssertion(credId, authData, clientData, signature);
	}

	private void fillEnroll(Callback[] callbacks, String token, long signCount) throws Exception {
		FidoAuthenticationCallback fidoCb = fido(callbacks);
		int flags = FidoAssertionVerifier.FLAG_UP | FidoAssertionVerifier.FLAG_UV |
			FidoAssertionVerifier.FLAG_AT;
		byte[] authData =
			FidoWebAuthnFixtures.authenticatorData(RP_ID, flags, signCount, credId, cose);
		byte[] clientData = FidoWebAuthnFixtures.clientDataJSON("webauthn.create",
			fidoCb.getChallenge(), ORIGIN);
		fidoCb.setAssertion(credId, authData, clientData, new byte[] { 0 });
		fidoCb.setAttestationObject(FidoWebAuthnFixtures.attestationNone(authData));
		fidoCb.setEnrollToken(token);
	}

	private void fillName(Callback[] callbacks, String username) {
		NameCallback nameCb =
			AuthenticationModule.getFirstCallbackOfType(NameCallback.class, callbacks);
		assertNotNull(nameCb);
		nameCb.setName(username);
	}

	private void assertAuthFailed(Callback[] callbacks) {
		try {
			module.authenticate(userMgr(), subject(USER), callbacks);
			fail("expected FailedLoginException");
		}
		catch (FailedLoginException e) {
			assertEquals("Authentication failed", e.getMessage());
		}
		catch (Exception e) {
			fail("unexpected " + e);
		}
	}

	private static FidoAuthenticationCallback fido(Callback[] callbacks) {
		return AuthenticationModule.getFirstCallbackOfType(FidoAuthenticationCallback.class,
			callbacks);
	}

	private static NameCallback name(String username) {
		NameCallback cb = new NameCallback("User ID:");
		cb.setName(username);
		return cb;
	}

	private static FidoAuthenticationCallback copyAssertion(Callback[] callbacks) {
		FidoAuthenticationCallback src = fido(callbacks);
		FidoAuthenticationCallback copy = new FidoAuthenticationCallback(src.getRpId(),
			src.getRpName(), src.getChallenge(), src.getAllowCredentials(), src.isEnroll(),
			src.getTimeoutSeconds());
		copy.setAssertion(src.getCredentialId(), src.getAuthenticatorData(),
			src.getClientDataJSON(), src.getSignature());
		return copy;
	}

	private static Subject subject(String username) {
		Subject subject = new Subject();
		subject.getPrincipals().add(new GhidraPrincipal(username));
		return subject;
	}

	private UserManager userMgr() {
		return mgr.getUserManager();
	}

	private FidoCredentialStore store() {
		return userMgr().getFidoCredentialStore();
	}

	private static void writeUsers(File serverRoot, String... users) throws IOException {
		StringBuilder buf = new StringBuilder();
		for (String user : users) {
			buf.append(user).append(":*:*\n");
		}
		FileUtilities.writeStringToFile(new File(serverRoot, UserManager.USER_PASSWORD_FILE),
			buf.toString());
	}
}
