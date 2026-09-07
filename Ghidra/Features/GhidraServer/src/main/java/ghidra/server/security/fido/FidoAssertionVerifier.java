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

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;
import java.util.*;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * Thin JDK+Gson WebAuthn L2 assertion and packed/none attestation verifier.
 * No CBOR, JOSE, or BouncyCastle libraries.
 */
public class FidoAssertionVerifier {

	static final int FLAG_UP = 0x01;
	static final int FLAG_UV = 0x04;
	static final int FLAG_AT = 0x40;

	private static final int AUTH_DATA_MIN = 37;
	private static final int AAGUID_LEN = 16;
	private static final int ES256_COORD_LEN = 32;
	private static final int ES256_RAW_SIG_LEN = 64;

	private static final int KTY_EC2 = 2;
	private static final int KTY_RSA = 3;
	private static final int ALG_ES256 = -7;
	private static final int ALG_RS256 = -257;
	private static final int CRV_P256 = 1;

	private static final int COSE_KTY = 1;
	private static final int COSE_ALG = 3;
	private static final int COSE_CRV_OR_N = -1;
	private static final int COSE_X_OR_E = -2;
	private static final int COSE_Y = -3;

	private static final String TYPE_GET = "webauthn.get";
	private static final String TYPE_CREATE = "webauthn.create";
	private static final String FMT_NONE = "none";
	private static final String FMT_PACKED = "packed";

	private static final int MAX_CLIENT_DATA_BYTES = 4096;
	private static final int MAX_ATTESTATION_BYTES = 8192;

	private final String rpId;
	private final byte[] rpIdHash;

	/**
	 * @param rpId WebAuthn relying-party id (stable hostname)
	 */
	public FidoAssertionVerifier(String rpId) {
		this.rpId = normalizeRpId(rpId);
		this.rpIdHash = sha256(this.rpId.getBytes(StandardCharsets.UTF_8));
	}

	/**
	 * Lowercase ASCII rpId. Rejects scheme, port, and path. {@code ::1} / {@code [::1]}
	 * are allowed loopback literals.
	 * @param rpId candidate relying-party id
	 * @return normalized rpId
	 */
	public static String normalizeRpId(String rpId) {
		if (rpId == null || rpId.isBlank()) {
			throw new IllegalArgumentException("rpId is required");
		}
		String n = rpId.trim().toLowerCase(Locale.ROOT);
		if (n.contains("://") || n.indexOf('/') >= 0 || n.indexOf(' ') >= 0) {
			throw new IllegalArgumentException("rpId must be a hostname or loopback literal");
		}
		int colon = n.indexOf(':');
		if (colon > 0 && n.indexOf(':', colon + 1) < 0) {
			throw new IllegalArgumentException("rpId must be a hostname or loopback literal");
		}
		return n;
	}

	/**
	 * {@return the configured relying-party id}
	 */
	public String getRpId() {
		return rpId;
	}

	/**
	 * Verify a WebAuthn assertion (login).
	 * @param challenge original challenge issued by the server
	 * @param authenticatorData WebAuthn authenticator data
	 * @param clientDataJSON WebAuthn clientDataJSON bytes
	 * @param signature assertion signature (ES256 raw r||s or DER; RS256 PKCS#1)
	 * @param publicKeyCose stored COSE_Key bytes
	 * @param storedSignCount previously stored signature counter
	 * @return verified signature counter from authenticator data
	 * @throws VerificationException if verification fails
	 */
	public long verifyAssertion(byte[] challenge, byte[] authenticatorData, byte[] clientDataJSON,
			byte[] signature, byte[] publicKeyCose, long storedSignCount)
			throws VerificationException {
		verifyClientData(clientDataJSON, challenge, TYPE_GET);
		ParsedAuthData authData = parseAuthenticatorData(authenticatorData, false);
		verifySignCount(storedSignCount, authData.signCount);
		PublicKey publicKey = parseCosePublicKey(publicKeyCose);
		verifySignature(publicKey, signedMessage(authenticatorData, clientDataJSON), signature);
		return authData.signCount;
	}

	/**
	 * Verify a WebAuthn attestation object for enrollment. Accepts {@code none} and
	 * packed self-attestation (signed with the new credential public key).
	 * @param challenge original challenge issued by the server
	 * @param authenticatorData authenticator data from the callback; if null, authData
	 *        from the attestation object is used
	 * @param clientDataJSON WebAuthn clientDataJSON bytes
	 * @param attestationObject CBOR attestation object
	 * @return parsed credential to persist
	 * @throws VerificationException if verification fails
	 */
	public Enrollment verifyAttestation(byte[] challenge, byte[] authenticatorData,
			byte[] clientDataJSON, byte[] attestationObject) throws VerificationException {
		if (attestationObject == null || attestationObject.length == 0) {
			throw new VerificationException("attestation object required");
		}
		if (attestationObject.length > MAX_ATTESTATION_BYTES) {
			throw new VerificationException("attestation object too large");
		}
		verifyClientData(clientDataJSON, challenge, TYPE_CREATE);

		CborDecoder decoder = new CborDecoder(attestationObject, 0);
		Map<Object, Object> attObj = decoder.readMap();
		decoder.checkConsumed();
		String fmt = textValue(attObj.get("fmt"));
		byte[] attAuthData = bytesValue(attObj.get("authData"));
		if (attAuthData == null) {
			throw new VerificationException("attestation authData required");
		}
		if (authenticatorData != null &&
			!MessageDigest.isEqual(authenticatorData, attAuthData)) {
			throw new VerificationException("authenticatorData mismatch");
		}

		ParsedAuthData parsed = parseAuthenticatorData(attAuthData, true);
		if (FMT_NONE.equals(fmt)) {
			Map<Object, Object> attStmt = mapValue(attObj.get("attStmt"));
			if (attStmt == null || !attStmt.isEmpty()) {
				throw new VerificationException("none attStmt must be empty");
			}
		}
		else if (FMT_PACKED.equals(fmt)) {
			verifyPackedSelfAttestation(mapValue(attObj.get("attStmt")), attAuthData,
				clientDataJSON, parsed.publicKeyCose);
		}
		else {
			throw new VerificationException("unsupported attestation format");
		}
		return new Enrollment(parsed.credentialId, parsed.publicKeyCose, parsed.signCount,
			parsed.aaguid);
	}

	private void verifyPackedSelfAttestation(Map<Object, Object> attStmt, byte[] authData,
			byte[] clientDataJSON, byte[] publicKeyCose) throws VerificationException {
		if (attStmt == null) {
			throw new VerificationException("packed attStmt required");
		}
		byte[] sig = bytesValue(attStmt.get("sig"));
		Long alg = longValue(attStmt.get("alg"));
		if (sig == null) {
			throw new VerificationException("packed attStmt signature required");
		}
		if (alg == null) {
			throw new VerificationException("packed attStmt algorithm required");
		}
		PublicKey publicKey = parseCosePublicKey(publicKeyCose);
		int expected = (publicKey instanceof ECPublicKey) ? ALG_ES256 : ALG_RS256;
		if (alg.intValue() != expected) {
			throw new VerificationException("packed attStmt algorithm mismatch");
		}
		verifySignature(publicKey, signedMessage(authData, clientDataJSON), sig);
	}

	private void verifyClientData(byte[] clientDataJSON, byte[] challenge, String expectedType)
			throws VerificationException {
		if (clientDataJSON == null || clientDataJSON.length == 0) {
			throw new VerificationException("clientDataJSON required");
		}
		if (clientDataJSON.length > MAX_CLIENT_DATA_BYTES) {
			throw new VerificationException("clientDataJSON too large");
		}
		if (challenge == null || challenge.length == 0) {
			throw new VerificationException("challenge required");
		}
		JsonObject obj;
		try {
			JsonElement element =
				JsonParser.parseString(new String(clientDataJSON, StandardCharsets.UTF_8));
			if (element == null || !element.isJsonObject()) {
				throw new VerificationException("invalid clientDataJSON");
			}
			obj = element.getAsJsonObject();
		}
		catch (VerificationException e) {
			throw e;
		}
		catch (RuntimeException | StackOverflowError e) {
			throw new VerificationException("invalid clientDataJSON");
		}
		String type = requiredString(obj, "type");
		if (!expectedType.equals(type)) {
			throw new VerificationException("unexpected clientDataJSON type");
		}
		byte[] gotChallenge;
		try {
			gotChallenge = Base64.getUrlDecoder().decode(requiredString(obj, "challenge"));
		}
		catch (IllegalArgumentException e) {
			throw new VerificationException("invalid clientDataJSON challenge");
		}
		if (!MessageDigest.isEqual(challenge, gotChallenge)) {
			throw new VerificationException("challenge mismatch");
		}
		if (!isAllowedOrigin(requiredString(obj, "origin"))) {
			throw new VerificationException("origin mismatch");
		}
	}

	private boolean isAllowedOrigin(String origin) {
		if (origin == null) {
			return false;
		}
		if (("https://" + rpId).equals(origin)) {
			return true;
		}
		if (!isLoopbackRpId(rpId)) {
			return false;
		}
		return "http://localhost".equals(origin) || "http://127.0.0.1".equals(origin) ||
			"http://[::1]".equals(origin) || "https://localhost".equals(origin) ||
			"https://127.0.0.1".equals(origin) || "https://[::1]".equals(origin);
	}

	static boolean isLoopbackRpId(String rpId) {
		String n = rpId.toLowerCase(Locale.ROOT);
		return "localhost".equals(n) || "127.0.0.1".equals(n) || "::1".equals(n) ||
			"[::1]".equals(n);
	}

	private ParsedAuthData parseAuthenticatorData(byte[] authData, boolean requireAttested)
			throws VerificationException {
		if (authData == null || authData.length < AUTH_DATA_MIN) {
			throw new VerificationException("authenticatorData truncated");
		}
		byte[] gotHash = Arrays.copyOfRange(authData, 0, 32);
		if (!MessageDigest.isEqual(rpIdHash, gotHash)) {
			throw new VerificationException("rpIdHash mismatch");
		}
		int flags = authData[32] & 0xff;
		if ((flags & FLAG_UP) == 0) {
			throw new VerificationException("user presence required");
		}
		if ((flags & FLAG_UV) == 0) {
			throw new VerificationException("user verification required");
		}
		long signCount = unsignedInt(authData, 33);
		if (requireAttested) {
			if ((flags & FLAG_AT) == 0) {
				throw new VerificationException("attested credential data required");
			}
			return parseAttestedCredential(authData, signCount);
		}
		return new ParsedAuthData(signCount, null, null, null);
	}

	private static ParsedAuthData parseAttestedCredential(byte[] authData, long signCount)
			throws VerificationException {
		int offset = AUTH_DATA_MIN;
		if (authData.length < offset + AAGUID_LEN + 2) {
			throw new VerificationException("attested credential data truncated");
		}
		byte[] aaguid = Arrays.copyOfRange(authData, offset, offset + AAGUID_LEN);
		offset += AAGUID_LEN;
		int credIdLen = ((authData[offset] & 0xff) << 8) | (authData[offset + 1] & 0xff);
		offset += 2;
		if (credIdLen <= 0 || authData.length < offset + credIdLen) {
			throw new VerificationException("credential id truncated");
		}
		byte[] credentialId = Arrays.copyOfRange(authData, offset, offset + credIdLen);
		offset += credIdLen;
		CborDecoder coseDecoder = new CborDecoder(authData, offset);
		coseDecoder.readMap();
		byte[] publicKeyCose = Arrays.copyOfRange(authData, offset, coseDecoder.position());
		parseCosePublicKey(publicKeyCose);
		return new ParsedAuthData(signCount, credentialId, publicKeyCose, aaguid);
	}

	static void verifySignCount(long storedSignCount, long newSignCount)
			throws VerificationException {
		if (storedSignCount > 0 && newSignCount < storedSignCount) {
			throw new VerificationException("signCount decreased");
		}
	}

	static PublicKey parseCosePublicKey(byte[] cose) throws VerificationException {
		if (cose == null || cose.length == 0) {
			throw new VerificationException("COSE key required");
		}
		CborDecoder decoder = new CborDecoder(cose, 0);
		Map<Object, Object> map = decoder.readMap();
		decoder.checkConsumed();
		Long kty = longValue(mapGet(map, COSE_KTY));
		Long alg = longValue(mapGet(map, COSE_ALG));
		if (kty == null) {
			throw new VerificationException("COSE kty required");
		}
		if (kty.intValue() == KTY_EC2) {
			if (alg != null && alg.intValue() != ALG_ES256) {
				throw new VerificationException("unsupported COSE alg");
			}
			Long crv = longValue(mapGet(map, COSE_CRV_OR_N));
			if (crv == null || crv.intValue() != CRV_P256) {
				throw new VerificationException("unsupported EC curve");
			}
			return parseEs256(bytesValue(mapGet(map, COSE_X_OR_E)),
				bytesValue(mapGet(map, COSE_Y)));
		}
		if (kty.intValue() == KTY_RSA) {
			if (alg != null && alg.intValue() != ALG_RS256) {
				throw new VerificationException("unsupported COSE alg");
			}
			return parseRs256(bytesValue(mapGet(map, COSE_CRV_OR_N)),
				bytesValue(mapGet(map, COSE_X_OR_E)));
		}
		throw new VerificationException("unsupported COSE kty");
	}

	private static PublicKey parseEs256(byte[] x, byte[] y) throws VerificationException {
		if (x == null || y == null || x.length != ES256_COORD_LEN || y.length != ES256_COORD_LEN) {
			throw new VerificationException("invalid ES256 coordinates");
		}
		try {
			AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
			params.init(new ECGenParameterSpec("secp256r1"));
			ECParameterSpec spec = params.getParameterSpec(ECParameterSpec.class);
			ECPoint point = new ECPoint(new BigInteger(1, x), new BigInteger(1, y));
			return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(point, spec));
		}
		catch (GeneralSecurityException e) {
			throw new VerificationException("invalid ES256 public key");
		}
	}

	private static PublicKey parseRs256(byte[] n, byte[] e) throws VerificationException {
		if (n == null || e == null || n.length == 0 || e.length == 0) {
			throw new VerificationException("invalid RS256 public key");
		}
		try {
			RSAPublicKeySpec spec =
				new RSAPublicKeySpec(new BigInteger(1, n), new BigInteger(1, e));
			return KeyFactory.getInstance("RSA").generatePublic(spec);
		}
		catch (GeneralSecurityException ex) {
			throw new VerificationException("invalid RS256 public key");
		}
	}

	private static void verifySignature(PublicKey publicKey, byte[] message, byte[] signature)
			throws VerificationException {
		if (signature == null || signature.length == 0) {
			throw new VerificationException("signature required");
		}
		try {
			if (publicKey instanceof ECPublicKey) {
				byte[] der =
					signature.length == ES256_RAW_SIG_LEN ? p1363ToDer(signature) : signature;
				verifyJca("SHA256withECDSA", publicKey, message, der);
			}
			else if (publicKey instanceof RSAPublicKey) {
				verifyJca("SHA256withRSA", publicKey, message, signature);
			}
			else {
				throw new VerificationException("unsupported public key");
			}
		}
		catch (VerificationException e) {
			throw e;
		}
		catch (GeneralSecurityException | RuntimeException e) {
			throw new VerificationException("invalid signature");
		}
	}

	private static void verifyJca(String algorithm, PublicKey publicKey, byte[] message,
			byte[] signature) throws GeneralSecurityException, VerificationException {
		Signature sig = Signature.getInstance(algorithm);
		sig.initVerify(publicKey);
		sig.update(message);
		if (!sig.verify(signature)) {
			throw new VerificationException("invalid signature");
		}
	}

	private static byte[] signedMessage(byte[] authenticatorData, byte[] clientDataJSON) {
		byte[] hash = sha256(clientDataJSON);
		byte[] msg = new byte[authenticatorData.length + hash.length];
		System.arraycopy(authenticatorData, 0, msg, 0, authenticatorData.length);
		System.arraycopy(hash, 0, msg, authenticatorData.length, hash.length);
		return msg;
	}

	static byte[] p1363ToDer(byte[] raw) throws VerificationException {
		if (raw == null || raw.length != ES256_RAW_SIG_LEN) {
			throw new VerificationException("invalid ES256 signature");
		}
		byte[] r = unsignedInteger(raw, 0, 32);
		byte[] s = unsignedInteger(raw, 32, 32);
		int seqLen = 2 + r.length + 2 + s.length;
		byte[] der = new byte[(seqLen < 128 ? 2 : 3) + seqLen];
		int i = 0;
		der[i++] = 0x30;
		if (seqLen < 128) {
			der[i++] = (byte) seqLen;
		}
		else {
			der[i++] = (byte) 0x81;
			der[i++] = (byte) seqLen;
		}
		der[i++] = 0x02;
		der[i++] = (byte) r.length;
		System.arraycopy(r, 0, der, i, r.length);
		i += r.length;
		der[i++] = 0x02;
		der[i++] = (byte) s.length;
		System.arraycopy(s, 0, der, i, s.length);
		return der;
	}

	private static byte[] unsignedInteger(byte[] src, int off, int len) {
		int start = off;
		int end = off + len;
		while (start < end - 1 && src[start] == 0) {
			start++;
		}
		boolean pad = (src[start] & 0x80) != 0;
		byte[] out = new byte[(end - start) + (pad ? 1 : 0)];
		System.arraycopy(src, start, out, pad ? 1 : 0, end - start);
		return out;
	}

	private static String requiredString(JsonObject obj, String name) throws VerificationException {
		try {
			if (!obj.has(name) || obj.get(name).isJsonNull()) {
				throw new VerificationException("clientDataJSON missing " + name);
			}
			return obj.get(name).getAsString();
		}
		catch (VerificationException e) {
			throw e;
		}
		catch (RuntimeException e) {
			throw new VerificationException("invalid clientDataJSON " + name);
		}
	}

	private static byte[] sha256(byte[] data) {
		try {
			return MessageDigest.getInstance("SHA-256").digest(data);
		}
		catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("SHA-256 not available", e);
		}
	}

	private static long unsignedInt(byte[] data, int offset) {
		return ((data[offset] & 0xffL) << 24) | ((data[offset + 1] & 0xffL) << 16) |
			((data[offset + 2] & 0xffL) << 8) | (data[offset + 3] & 0xffL);
	}

	private static Object mapGet(Map<Object, Object> map, int key) {
		return map.get(Long.valueOf(key));
	}

	private static Long longValue(Object value) {
		return (value instanceof Long) ? (Long) value : null;
	}

	private static byte[] bytesValue(Object value) {
		return (value instanceof byte[]) ? (byte[]) value : null;
	}

	private static String textValue(Object value) {
		return (value instanceof String) ? (String) value : null;
	}

	@SuppressWarnings("unchecked")
	private static Map<Object, Object> mapValue(Object value) {
		return (value instanceof Map) ? (Map<Object, Object>) value : null;
	}

	/**
	 * Parsed attested credential produced during enrollment.
	 */
	public static final class Enrollment {
		private final byte[] credentialId;
		private final byte[] publicKeyCose;
		private final long signCount;
		private final byte[] aaguid;

		Enrollment(byte[] credentialId, byte[] publicKeyCose, long signCount, byte[] aaguid) {
			this.credentialId = credentialId;
			this.publicKeyCose = publicKeyCose;
			this.signCount = signCount;
			this.aaguid = aaguid;
		}

		public byte[] getCredentialId() {
			return credentialId.clone();
		}

		public byte[] getPublicKeyCose() {
			return publicKeyCose.clone();
		}

		public long getSignCount() {
			return signCount;
		}

		public byte[] getAaguid() {
			return aaguid.clone();
		}
	}

	/**
	 * Verification failure. Message is safe to log (no payloads).
	 */
	public static class VerificationException extends Exception {
		public VerificationException(String message) {
			super(message);
		}
	}

	private static final class ParsedAuthData {
		private final long signCount;
		private final byte[] credentialId;
		private final byte[] publicKeyCose;
		private final byte[] aaguid;

		private ParsedAuthData(long signCount, byte[] credentialId, byte[] publicKeyCose,
				byte[] aaguid) {
			this.signCount = signCount;
			this.credentialId = credentialId;
			this.publicKeyCose = publicKeyCose;
			this.aaguid = aaguid;
		}
	}

	/**
	 * Tiny CBOR decoder for maps of ints/bytes/text used by COSE_Key and attestation objects.
	 */
	static final class CborDecoder {
		private static final int MAX_DEPTH = 2;
		private static final int MAX_BYTES = 8192;
		private static final int MAX_ITEMS = 16;
		private static final int MAX_DECODED_VALUES = 64;

		private final byte[] data;
		private int offset;
		private int decodedValues;

		CborDecoder(byte[] data, int offset) {
			this.data = data;
			this.offset = offset;
		}

		int position() {
			return offset;
		}

		void checkConsumed() throws VerificationException {
			if (offset != data.length) {
				throw new VerificationException("trailing CBOR");
			}
		}

		Map<Object, Object> readMap() throws VerificationException {
			Object value = read(0);
			if (!(value instanceof Map)) {
				throw new VerificationException("CBOR map required");
			}
			@SuppressWarnings("unchecked")
			Map<Object, Object> map = (Map<Object, Object>) value;
			return map;
		}

		private Object read(int depth) throws VerificationException {
			if (depth > MAX_DEPTH) {
				throw new VerificationException("CBOR nesting too deep");
			}
			if (++decodedValues > MAX_DECODED_VALUES) {
				throw new VerificationException("CBOR too large");
			}
			int ib = readByte();
			int major = ib >>> 5;
			int ai = ib & 0x1f;
			long n = additional(ai);
			switch (major) {
				case 0:
					return Long.valueOf(n);
				case 1:
					if (n == Long.MAX_VALUE) {
						throw new VerificationException("CBOR integer overflow");
					}
					return Long.valueOf(-1L - n);
				case 2:
					return readExact(toLength(n));
				case 3:
					return new String(readExact(toLength(n)), StandardCharsets.UTF_8);
				case 4:
					throw new VerificationException("unsupported CBOR array");
				case 5: {
					int len = toCount(n);
					Map<Object, Object> map = new LinkedHashMap<>();
					for (int i = 0; i < len; i++) {
						Object key = read(depth + 1);
						if (!(key instanceof Long) && !(key instanceof String)) {
							throw new VerificationException("unsupported CBOR map key");
						}
						Object val = read(depth + 1);
						if (map.containsKey(key)) {
							throw new VerificationException("duplicate CBOR map key");
						}
						map.put(key, val);
					}
					return map;
				}
				case 6:
					throw new VerificationException("unsupported CBOR tag");
				case 7:
					throw new VerificationException("unsupported CBOR simple value");
				default:
					throw new VerificationException("unsupported CBOR type");
			}
		}

		private long additional(int ai) throws VerificationException {
			if (ai < 24) {
				return ai;
			}
			int bytes;
			switch (ai) {
				case 24:
					bytes = 1;
					break;
				case 25:
					bytes = 2;
					break;
				case 26:
					bytes = 4;
					break;
				case 27:
					bytes = 8;
					break;
				default:
					throw new VerificationException("unsupported CBOR additional info");
			}
			long v = 0;
			for (int i = 0; i < bytes; i++) {
				v = (v << 8) | readByte();
			}
			if (v < 0) {
				throw new VerificationException("CBOR integer overflow");
			}
			return v;
		}

		private int toLength(long n) throws VerificationException {
			if (n < 0 || n > MAX_BYTES) {
				throw new VerificationException("CBOR length invalid");
			}
			return (int) n;
		}

		private int toCount(long n) throws VerificationException {
			if (n < 0 || n > MAX_ITEMS) {
				throw new VerificationException("CBOR item count invalid");
			}
			return (int) n;
		}

		private int readByte() throws VerificationException {
			if (offset >= data.length) {
				throw new VerificationException("truncated CBOR");
			}
			return data[offset++] & 0xff;
		}

		private byte[] readExact(int len) throws VerificationException {
			if (len < 0 || offset + len > data.length) {
				throw new VerificationException("truncated CBOR");
			}
			byte[] out = Arrays.copyOfRange(data, offset, offset + len);
			offset += len;
			return out;
		}
	}
}
