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

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;

/**
 * Builds WebAuthn assertion/attestation payloads for tests (no native helper).
 */
final class FidoWebAuthnFixtures {

	static final byte[] CRED_ID = bytes(0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA,
		0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00);
	static final byte[] AAGUID = new byte[16];

	private FidoWebAuthnFixtures() {
		// fixtures
	}

	static KeyPair es256() throws GeneralSecurityException {
		KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
		gen.initialize(new ECGenParameterSpec("secp256r1"));
		return gen.generateKeyPair();
	}

	static KeyPair rs256() throws GeneralSecurityException {
		KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
		gen.initialize(2048);
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

	static byte[] coseRs256(RSAPublicKey pub) {
		return coseRs256Raw(unsignedBytes(pub.getModulus()),
			unsignedBytes(pub.getPublicExponent()));
	}

	static byte[] coseRs256Raw(byte[] n, byte[] e) {
		CborWriter w = new CborWriter();
		w.map(4);
		w.integer(1).integer(3);
		w.integer(3).integer(-257);
		w.integer(-1).bytes(n);
		w.integer(-2).bytes(e);
		return w.toByteArray();
	}

	static byte[] coseEs256WithoutAlg(ECPublicKey pub) {
		byte[] x = unsignedCoord(pub.getW().getAffineX(), 32);
		byte[] y = unsignedCoord(pub.getW().getAffineY(), 32);
		CborWriter w = new CborWriter();
		w.map(4);
		w.integer(1).integer(2);
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

	static byte[] authenticatorData(String rpId, int flags, long signCount) {
		return authenticatorData(rpId, flags, signCount, null, null);
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
		sig.update(signedMessage(authenticatorData, clientDataJSON));
		return sig.sign();
	}

	static byte[] signRs256(PrivateKey priv, byte[] authenticatorData, byte[] clientDataJSON)
			throws GeneralSecurityException {
		Signature sig = Signature.getInstance("SHA256withRSA");
		sig.initSign(priv);
		sig.update(signedMessage(authenticatorData, clientDataJSON));
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

	static byte[] attestationPacked(byte[] authData, byte[] clientDataJSON, PrivateKey priv,
			boolean es256) throws GeneralSecurityException {
		byte[] sig = es256 ? signEs256(priv, authData, clientDataJSON)
				: signRs256(priv, authData, clientDataJSON);
		return attestationPacked(authData, sig, es256, true);
	}

	static byte[] attestationPacked(byte[] authData, byte[] sig, boolean es256, boolean includeAlg) {
		CborWriter stmt = new CborWriter();
		stmt.map(includeAlg ? 2 : 1);
		if (includeAlg) {
			stmt.text("alg").integer(es256 ? -7 : -257);
		}
		stmt.text("sig").bytes(sig);
		CborWriter w = new CborWriter();
		w.map(3);
		w.text("fmt").text("packed");
		w.text("attStmt").raw(stmt.toByteArray());
		w.text("authData").bytes(authData);
		return w.toByteArray();
	}

	static byte[] attestationNoneWithStmt(byte[] authData, boolean emptyStmt) {
		CborWriter w = new CborWriter();
		w.map(3);
		w.text("fmt").text("none");
		if (emptyStmt) {
			w.text("attStmt").map(0);
		}
		else {
			CborWriter stmt = new CborWriter();
			stmt.map(1);
			stmt.text("x").integer(1);
			w.text("attStmt").raw(stmt.toByteArray());
		}
		w.text("authData").bytes(authData);
		return w.toByteArray();
	}

	static byte[] attestationFmt(byte[] authData, String fmt) {
		CborWriter w = new CborWriter();
		w.map(3);
		w.text("fmt").text(fmt);
		w.text("attStmt").map(0);
		w.text("authData").bytes(authData);
		return w.toByteArray();
	}

	static byte[] concat(byte[] a, byte[] b) {
		byte[] out = new byte[a.length + b.length];
		System.arraycopy(a, 0, out, 0, a.length);
		System.arraycopy(b, 0, out, a.length, b.length);
		return out;
	}

	static byte[] signedMessage(byte[] authenticatorData, byte[] clientDataJSON)
			throws GeneralSecurityException {
		byte[] hash = MessageDigest.getInstance("SHA-256").digest(clientDataJSON);
		byte[] msg = new byte[authenticatorData.length + hash.length];
		System.arraycopy(authenticatorData, 0, msg, 0, authenticatorData.length);
		System.arraycopy(hash, 0, msg, authenticatorData.length, hash.length);
		return msg;
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

	private static byte[] unsignedBytes(BigInteger v) {
		byte[] raw = v.toByteArray();
		if (raw.length > 1 && raw[0] == 0) {
			return Arrays.copyOfRange(raw, 1, raw.length);
		}
		return raw;
	}

	static final class CborWriter {
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

		CborWriter raw(byte[] b) {
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
