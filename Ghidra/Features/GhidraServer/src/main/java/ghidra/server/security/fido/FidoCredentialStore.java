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

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.*;
import java.util.regex.Pattern;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonSyntaxException;
import com.google.gson.reflect.TypeToken;

import generic.hash.HashUtilities;
import generic.random.SecureRandomFactory;
import ghidra.framework.store.local.LocalFileSystem;
import ghidra.server.UserManager;
import ghidra.util.NumericUtilities;
import utilities.util.FileUtilities;

/**
 * Persists FIDO2 credentials and one-time enrollment tokens under
 * {@code <repositories>/~fido/}, following the {@code ~ssh/} sidecar layout.
 * <p>
 * Each user has:
 * <ul>
 *   <li>{@code <username>.json} — JSON array of {@link FidoCredential}</li>
 *   <li>{@code <username>.enroll} — hashed one-time enroll token and expiry</li>
 * </ul>
 * All mutating methods are one-shot with respect to enroll tokens and are
 * synchronized on this store instance. File writes are temp-file + rename.
 */
public class FidoCredentialStore {

	public static final String FIDO_DIR_NAME = LocalFileSystem.HIDDEN_DIR_PREFIX + "fido";
	public static final String CREDENTIAL_FILE_EXT = ".json";
	public static final String ENROLL_FILE_EXT = ".enroll";

	/**
	 * Default enroll-token lifetime (15 minutes).
	 */
	public static final long DEFAULT_ENROLL_TTL_MS = 15L * 60L * 1000L;

	private static final int ENROLL_TOKEN_BYTES = 20;
	private static final int TOKEN_HASH_BYTES = 32;
	private static final Pattern TOKEN_HASH_PATTERN = Pattern.compile("[0-9a-f]{64}");
	private static final Gson GSON =
		new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
	private static final Type CREDENTIAL_LIST_TYPE =
		new TypeToken<List<FidoCredential>>() {}.getType();

	private final File fidoDir;

	/**
	 * Construct a store rooted at the server repositories directory.
	 * @param repositoriesRootDir repositories root (contains the {@code users} file)
	 */
	public FidoCredentialStore(File repositoriesRootDir) {
		if (repositoriesRootDir == null) {
			throw new IllegalArgumentException("repositoriesRootDir is required");
		}
		this.fidoDir = new File(repositoriesRootDir, FIDO_DIR_NAME);
		try {
			getFidoDir();
		}
		catch (IOException e) {
			// retried on first use
		}
	}

	/**
	 * Generate a high-entropy URL-safe one-time enroll code (20 random bytes,
	 * unpadded base64url, 27 characters).
	 * @return plaintext enroll token
	 */
	public static String generateEnrollToken() {
		byte[] bytes = new byte[ENROLL_TOKEN_BYTES];
		SecureRandomFactory.getSecureRandom().nextBytes(bytes);
		return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
	}

	/**
	 * SHA-256 hash of the plaintext enroll token as lowercase hex.
	 * @param plaintext enroll token
	 * @return 64-character hex digest
	 */
	public static String hashEnrollToken(String plaintext) {
		if (plaintext == null) {
			throw new IllegalArgumentException("plaintext is required");
		}
		return HashUtilities.getHash(HashUtilities.SHA256_ALGORITHM,
			plaintext.getBytes(StandardCharsets.UTF_8));
	}

	/**
	 * {@return the {@code ~fido} directory, creating it if needed}
	 * @throws IOException if the directory cannot be created
	 */
	File getFidoDir() throws IOException {
		if (!fidoDir.isDirectory()) {
			if (!fidoDir.mkdirs() && !fidoDir.isDirectory()) {
				throw new IOException("Failed to create FIDO directory: " + fidoDir);
			}
		}
		setOwnerOnlyDirectory(fidoDir);
		return fidoDir;
	}

	/**
	 * Load registered credentials for {@code username}. Missing file yields an empty list.
	 * @param username user name/SID
	 * @return mutable list of credentials (never null)
	 * @throws IOException if the file cannot be read or parsed
	 * @throws IllegalArgumentException if {@code username} is not a valid user name
	 */
	public synchronized List<FidoCredential> loadCredentials(String username) throws IOException {
		checkUserName(username);
		File file = credentialFile(username);
		if (!file.isFile()) {
			return new ArrayList<>();
		}
		String json = FileUtilities.getText(file);
		if (json == null || json.isBlank()) {
			return new ArrayList<>();
		}
		try {
			List<FidoCredential> list = GSON.fromJson(json, CREDENTIAL_LIST_TYPE);
			if (list == null) {
				return new ArrayList<>();
			}
			List<FidoCredential> copy = new ArrayList<>();
			for (FidoCredential credential : list) {
				if (credential != null && credential.getCredentialId() != null) {
					copy.add(credential);
				}
			}
			return copy;
		}
		catch (JsonSyntaxException e) {
			throw new IOException("Failed to parse FIDO credentials for user '" + username + "'",
				e);
		}
	}

	/**
	 * Replace the stored credential list for {@code username}. An empty list deletes the file.
	 * @param username user name/SID
	 * @param credentials credentials to store (null treated as empty)
	 * @throws IOException if the file cannot be written
	 * @throws IllegalArgumentException if {@code username} is not a valid user name
	 */
	public synchronized void saveCredentials(String username, List<FidoCredential> credentials)
			throws IOException {
		checkUserName(username);
		File file = credentialFile(username);
		if (credentials == null || credentials.isEmpty()) {
			deleteQuietly(file);
			return;
		}
		writeAtomically(file, GSON.toJson(credentials, CREDENTIAL_LIST_TYPE));
	}

	/**
	 * Add or replace a credential by {@link FidoCredential#getCredentialId()}.
	 * @param username user name/SID
	 * @param credential credential to store
	 * @throws IOException if the file cannot be written
	 * @throws IllegalArgumentException if {@code username} or {@code credential} is invalid
	 */
	public synchronized void addCredential(String username, FidoCredential credential)
			throws IOException {
		if (credential == null || credential.getCredentialId() == null ||
			credential.getCredentialId().isBlank()) {
			throw new IllegalArgumentException("credential with id is required");
		}
		List<FidoCredential> list = loadCredentials(username);
		boolean replaced = false;
		for (int i = 0; i < list.size(); i++) {
			if (credential.getCredentialId().equals(list.get(i).getCredentialId())) {
				list.set(i, credential);
				replaced = true;
				break;
			}
		}
		if (!replaced) {
			list.add(credential);
		}
		saveCredentials(username, list);
	}

	/**
	 * Update the stored signature counter for a credential.
	 * @param username user name/SID
	 * @param credentialId unpadded base64url credential id
	 * @param signCount new signature counter
	 * @return true if the credential was found and updated
	 * @throws IOException if the file cannot be written
	 * @throws IllegalArgumentException if {@code username} is not a valid user name
	 */
	public synchronized boolean updateSignCount(String username, String credentialId,
			long signCount) throws IOException {
		if (credentialId == null) {
			return false;
		}
		List<FidoCredential> list = loadCredentials(username);
		boolean updated = false;
		for (int i = 0; i < list.size(); i++) {
			FidoCredential existing = list.get(i);
			if (credentialId.equals(existing.getCredentialId())) {
				list.set(i, existing.withSignCount(signCount));
				updated = true;
				break;
			}
		}
		if (updated) {
			saveCredentials(username, list);
		}
		return updated;
	}

	/**
	 * Remove a single credential. Does not affect a pending enroll token.
	 * @param username user name/SID
	 * @param credentialId unpadded base64url credential id
	 * @return true if a credential was removed
	 * @throws IOException if the file cannot be written
	 * @throws IllegalArgumentException if {@code username} is not a valid user name
	 */
	public synchronized boolean removeCredential(String username, String credentialId)
			throws IOException {
		if (credentialId == null) {
			return false;
		}
		List<FidoCredential> list = loadCredentials(username);
		boolean removed = list.removeIf(c -> credentialId.equals(c.getCredentialId()));
		if (removed) {
			saveCredentials(username, list);
		}
		return removed;
	}

	/**
	 * Delete all credentials and any pending enroll token for {@code username}.
	 * @param username user name/SID
	 * @throws IOException if a file cannot be deleted
	 * @throws IllegalArgumentException if {@code username} is not a valid user name
	 */
	public synchronized void removeAll(String username) throws IOException {
		checkUserName(username);
		deleteOrThrow(credentialFile(username));
		deleteOrThrow(enrollFile(username));
	}

	/**
	 * Store a hashed enroll token and expiry, replacing any previous token.
	 * @param username user name/SID
	 * @param hash SHA-256 hex digest of the plaintext token (exactly 64 hex characters)
	 * @param expiresEpochMs expiration time in milliseconds since the epoch
	 * @throws IOException if the file cannot be written
	 * @throws IllegalArgumentException if {@code username} or {@code hash} is invalid
	 */
	public synchronized void issueEnrollTokenHash(String username, String hash,
			long expiresEpochMs) throws IOException {
		checkUserName(username);
		byte[] digest = decodeTokenHash(hash);
		if (digest == null) {
			throw new IllegalArgumentException("token hash must be 64 hex characters");
		}
		EnrollTokenRecord record = new EnrollTokenRecord();
		record.tokenHash = hash.trim().toLowerCase(Locale.ROOT);
		record.expiresEpochMs = expiresEpochMs;
		writeAtomically(enrollFile(username), GSON.toJson(record));
	}

	/**
	 * Consume a plaintext enroll token. Succeeds at most once: the file is deleted
	 * only when the hash matches and the token has not expired. Wrong tokens do not
	 * consume a still-valid token. Expired tokens are deleted and rejected.
	 * @param username user name/SID
	 * @param plaintext one-time enroll code
	 * @return true if the token was valid and is now consumed
	 * @throws IOException if the file cannot be read or deleted
	 * @throws IllegalArgumentException if {@code username} is not a valid user name
	 */
	public synchronized boolean consumeEnrollToken(String username, String plaintext)
			throws IOException {
		if (!matchesEnrollToken(username, plaintext)) {
			return false;
		}
		deleteOrThrow(enrollFile(username));
		return true;
	}

	/**
	 * Check a plaintext enroll token without consuming it. Expired tokens are
	 * deleted and rejected. Wrong tokens do not consume a still-valid token.
	 * @param username user name/SID
	 * @param plaintext one-time enroll code
	 * @return true if the token is present, unexpired, and matches
	 * @throws IOException if the file cannot be read
	 * @throws IllegalArgumentException if {@code username} is not a valid user name
	 */
	public synchronized boolean matchesEnrollToken(String username, String plaintext)
			throws IOException {
		checkUserName(username);
		File file = enrollFile(username);
		EnrollTokenRecord record = readEnrollRecord(file);
		if (record == null) {
			return false;
		}
		if (isExpired(record)) {
			deleteQuietly(file);
			return false;
		}
		if (plaintext == null || !hashesEqual(record.tokenHash, hashEnrollToken(plaintext))) {
			return false;
		}
		return true;
	}

	/**
	 * {@return true if a non-expired enroll token is stored for {@code username}}
	 * @param username user name/SID
	 * @throws IOException if the enroll file cannot be read
	 * @throws IllegalArgumentException if {@code username} is not a valid user name
	 */
	public synchronized boolean hasPendingEnrollToken(String username) throws IOException {
		checkUserName(username);
		File file = enrollFile(username);
		EnrollTokenRecord record = readEnrollRecord(file);
		if (record == null) {
			return false;
		}
		if (isExpired(record)) {
			deleteQuietly(file);
			return false;
		}
		return true;
	}

	/**
	 * {@return expiry epoch milliseconds of a pending enroll token, or -1 if none}
	 * @param username user name/SID
	 * @throws IOException if the enroll file cannot be read
	 */
	public synchronized long getPendingEnrollExpiryEpochMs(String username) throws IOException {
		checkUserName(username);
		EnrollTokenRecord record = readEnrollRecord(enrollFile(username));
		if (record == null || isExpired(record)) {
			return -1L;
		}
		return record.expiresEpochMs;
	}

	private EnrollTokenRecord readEnrollRecord(File file) throws IOException {
		if (!file.isFile()) {
			return null;
		}
		String json = FileUtilities.getText(file);
		if (json == null || json.isBlank()) {
			return null;
		}
		try {
			EnrollTokenRecord record = GSON.fromJson(json, EnrollTokenRecord.class);
			if (record == null || record.tokenHash == null || record.tokenHash.isBlank()) {
				return null;
			}
			return record;
		}
		catch (JsonSyntaxException e) {
			throw new IOException("Failed to parse FIDO enroll token file: " + file.getName(), e);
		}
	}

	private static boolean isExpired(EnrollTokenRecord record) {
		return record.expiresEpochMs <= System.currentTimeMillis();
	}

	private static boolean hashesEqual(String storedHex, String actualHex) {
		byte[] stored = decodeTokenHash(storedHex);
		byte[] actual = decodeTokenHash(actualHex);
		if (stored == null || actual == null) {
			return false;
		}
		return MessageDigest.isEqual(stored, actual);
	}

	/**
	 * Decode a SHA-256 hex digest to 32 raw bytes, or null if it is not
	 * exactly 64 lowercase/uppercase hex characters.
	 * @param hash candidate hex digest
	 * @return 32-byte digest, or null if malformed
	 */
	static byte[] decodeTokenHash(String hash) {
		if (hash == null) {
			return null;
		}
		String normalized = hash.trim().toLowerCase(Locale.ROOT);
		if (!TOKEN_HASH_PATTERN.matcher(normalized).matches()) {
			return null;
		}
		byte[] digest = NumericUtilities.convertStringToBytes(normalized);
		if (digest == null || digest.length != TOKEN_HASH_BYTES) {
			return null;
		}
		return digest;
	}

	private File credentialFile(String username) throws IOException {
		return new File(getFidoDir(), username + CREDENTIAL_FILE_EXT);
	}

	private File enrollFile(String username) throws IOException {
		return new File(getFidoDir(), username + ENROLL_FILE_EXT);
	}

	private static void setOwnerOnlyDirectory(File dir) {
		FileUtilities.setOwnerOnlyPermissions(dir);
		dir.setExecutable(false, false);
		dir.setExecutable(true, true);
	}

	private void writeAtomically(File file, String json) throws IOException {
		File dir = getFidoDir();
		File tmp = File.createTempFile(file.getName(), ".tmp", dir);
		try {
			FileUtilities.writeStringToFile(tmp, json);
			FileUtilities.setOwnerOnlyPermissions(tmp);
			try {
				Files.move(tmp.toPath(), file.toPath(), StandardCopyOption.ATOMIC_MOVE,
					StandardCopyOption.REPLACE_EXISTING);
			}
			catch (AtomicMoveNotSupportedException e) {
				Files.move(tmp.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING);
			}
			FileUtilities.setOwnerOnlyPermissions(file);
			tmp = null;
		}
		finally {
			if (tmp != null) {
				tmp.delete();
			}
		}
	}

	private static void deleteQuietly(File file) {
		if (file.exists()) {
			file.delete();
		}
	}

	private static void deleteOrThrow(File file) throws IOException {
		if (file.exists() && !file.delete()) {
			throw new IOException("Failed to delete " + file);
		}
	}

	private static void checkUserName(String username) {
		if (username == null || !UserManager.isValidUserName(username)) {
			throw new IllegalArgumentException("Invalid username: " + username);
		}
	}

	/**
	 * On-disk enroll-token record.
	 */
	static class EnrollTokenRecord {
		String tokenHash;
		long expiresEpochMs;
	}
}
