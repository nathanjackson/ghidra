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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.framework.client.fido.FidoHelper;

/**
 * Test-only {@link FidoHelper} that produces valid ES256 WebAuthn create/assert
 * payloads. Duplicates the signer used by GhidraServer's FidoWebAuthnFixtures
 * because those fixtures are not on the IntegrationTest classpath.
 */
final class MockEs256FidoHelper implements FidoHelper {

	static final int FLAG_UP = 0x01;
	static final int FLAG_UV = 0x04;
	static final int FLAG_AT = 0x40;

	static final byte[] CRED_ID = bytes(0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA,
		0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00);
	static final byte[] AAGUID = new byte[16];

	private KeyPair keyPair;
	private byte[] cose;
	private long nextSignCount;

	MockEs256FidoHelper() {
		rotateKey();
	}

	/**
	 * Replace the credential keypair (used to simulate a wrong authenticator).
	 * Sign-count is left unchanged so a later assertion fails on the signature,
	 * not a decreased counter.
	 */
	void rotateKey() {
		try {
			keyPair = es256();
			cose = coseEs256((ECPublicKey) keyPair.getPublic());
		}
		catch (GeneralSecurityException e) {
			throw new IllegalStateException(e);
		}
	}

	@Override
	public String execute(String requestJson, int timeoutMs) throws IOException {
		JsonObject req;
		try {
			req = JsonParser.parseString(requestJson).getAsJsonObject();
		}
		catch (RuntimeException e) {
			throw new IOException("invalid FIDO helper request");
		}
		String op = stringField(req, "op");
		String rpId = stringField(req, "rpId");
		String origin = stringField(req, "origin");
		byte[] challenge = decodeB64(stringField(req, "challenge"));
		if (rpId == null || origin == null || challenge == null) {
			throw new IOException("FIDO helper request missing rpId, origin, or challenge");
		}
		boolean create = "create".equals(op);
		try {
			return create ? createResponse(rpId, origin, challenge)
					: assertResponse(rpId, origin, challenge);
		}
		catch (GeneralSecurityException e) {
			throw new IOException("mock authenticator failed", e);
		}
	}

	private String createResponse(String rpId, String origin, byte[] challenge)
			throws GeneralSecurityException {
		int flags = FLAG_UP | FLAG_UV | FLAG_AT;
		byte[] authData = authenticatorData(rpId, flags, nextSignCount++, CRED_ID, cose);
		byte[] clientData = clientDataJSON("webauthn.create", challenge, origin);
		byte[] signature = signEs256(keyPair.getPrivate(), authData, clientData);
		byte[] attestation = attestationNone(authData);
		return responseJson(CRED_ID, authData, clientData, signature, attestation);
	}

	private String assertResponse(String rpId, String origin, byte[] challenge)
			throws GeneralSecurityException {
		int flags = FLAG_UP | FLAG_UV;
		byte[] authData = authenticatorData(rpId, flags, nextSignCount++, null, null);
		byte[] clientData = clientDataJSON("webauthn.get", challenge, origin);
		byte[] signature = signEs256(keyPair.getPrivate(), authData, clientData);
		return responseJson(CRED_ID, authData, clientData, signature, null);
	}

	private static String responseJson(byte[] credentialId, byte[] authData, byte[] clientData,
			byte[] signature, byte[] attestation) {
		JsonObject obj = new JsonObject();
		obj.addProperty("credentialId", b64(credentialId));
		obj.addProperty("authenticatorData", b64(authData));
		obj.addProperty("clientDataJSON", b64(clientData));
		obj.addProperty("signature", b64(signature));
		if (attestation != null) {
			obj.addProperty("attestationObject", b64(attestation));
		}
		return obj.toString();
	}

	static KeyPair es256() throws GeneralSecurityException {
		KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
		gen.initialize(new ECGenParameterSpec("secp256r1"));
		return gen.generateKeyPair();
	}

	static byte[] coseEs256(ECPublicKey pub) {
		byte[] x = unsignedCoord(pub.getW().getAffineX(), 32);
		byte[] y = unsignedCoord(pub.getW().getAffineY(), 32);
		CborWriter w = new CborWriter();
		w.map(5);
		w.integer(1).integer(2);
		w.integer(3).integer(-7);
		w.integer(-1).integer(1);
		w.integer(-2).bytes(x);
		w.integer(-3).bytes(y);
		return w.toByteArray();
	}

	static byte[] clientDataJSON(String type, byte[] challenge, String origin) {
		String json = "{\"type\":\"" + type + "\",\"challenge\":\"" + b64(challenge) +
			"\",\"origin\":\"" + origin + "\"}";
		return json.getBytes(StandardCharsets.UTF_8);
	}

	static byte[] authenticatorData(String rpId, int flags, long signCount, byte[] credId,
			byte[] coseKey) {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			byte[] rpIdHash = md.digest(rpId.getBytes(StandardCharsets.UTF_8));
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			out.write(rpIdHash);
			out.write(flags);
			out.write((int) (signCount >> 24) & 0xff);
			out.write((int) (signCount >> 16) & 0xff);
			out.write((int) (signCount >> 8) & 0xff);
			out.write((int) signCount & 0xff);
			if (credId != null) {
				out.write(AAGUID);
				out.write((credId.length >> 8) & 0xff);
				out.write(credId.length & 0xff);
				out.write(credId);
				out.write(coseKey);
			}
			return out.toByteArray();
		}
		catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}

	static byte[] signEs256(PrivateKey priv, byte[] authenticatorData, byte[] clientDataJSON)
			throws GeneralSecurityException {
		Signature sig = Signature.getInstance("SHA256withECDSAinP1363Format");
		sig.initSign(priv);
		byte[] hash = MessageDigest.getInstance("SHA-256").digest(clientDataJSON);
		byte[] msg = new byte[authenticatorData.length + hash.length];
		System.arraycopy(authenticatorData, 0, msg, 0, authenticatorData.length);
		System.arraycopy(hash, 0, msg, authenticatorData.length, hash.length);
		sig.update(msg);
		return sig.sign();
	}

	static byte[] attestationNone(byte[] authData) {
		CborWriter w = new CborWriter();
		w.map(3);
		w.text("fmt").text("none");
		w.text("attStmt").map(0);
		w.text("authData").bytes(authData);
		return w.toByteArray();
	}

	static String b64(byte[] data) {
		return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
	}

	static byte[] bytes(int... values) {
		byte[] out = new byte[values.length];
		for (int i = 0; i < values.length; i++) {
			out[i] = (byte) values[i];
		}
		return out;
	}

	private static byte[] decodeB64(String data) {
		if (data == null || data.isBlank()) {
			return null;
		}
		try {
			return Base64.getUrlDecoder().decode(data);
		}
		catch (IllegalArgumentException e) {
			return null;
		}
	}

	private static String stringField(JsonObject obj, String name) {
		if (!obj.has(name) || obj.get(name).isJsonNull()) {
			return null;
		}
		try {
			return obj.get(name).getAsString();
		}
		catch (RuntimeException e) {
			return null;
		}
	}

	private static byte[] unsignedCoord(BigInteger v, int size) {
		byte[] raw = v.toByteArray();
		byte[] out = new byte[size];
		if (raw.length >= size) {
			System.arraycopy(raw, raw.length - size, out, 0, size);
		}
		else {
			System.arraycopy(raw, 0, out, size - raw.length, raw.length);
		}
		return out;
	}

	private static final class CborWriter {
		private final ByteArrayOutputStream out = new ByteArrayOutputStream();

		CborWriter map(int n) {
			header(5, n);
			return this;
		}

		CborWriter integer(long v) {
			if (v >= 0) {
				header(0, v);
			}
			else {
				header(1, -1 - v);
			}
			return this;
		}

		CborWriter bytes(byte[] b) {
			header(2, b.length);
			out.write(b, 0, b.length);
			return this;
		}

		CborWriter text(String s) {
			byte[] b = s.getBytes(StandardCharsets.UTF_8);
			header(3, b.length);
			out.write(b, 0, b.length);
			return this;
		}

		byte[] toByteArray() {
			return out.toByteArray();
		}

		private void header(int major, long n) {
			int mt = major << 5;
			if (n < 24) {
				out.write(mt | (int) n);
			}
			else if (n < 256) {
				out.write(mt | 24);
				out.write((int) n);
			}
			else if (n < 65536) {
				out.write(mt | 25);
				out.write((int) (n >> 8));
				out.write((int) n);
			}
			else {
				out.write(mt | 26);
				out.write((int) (n >> 24));
				out.write((int) (n >> 16));
				out.write((int) (n >> 8));
				out.write((int) n);
			}
		}
	}
}
