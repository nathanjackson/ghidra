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
#include "ghidra-fido-json.h"

#include <fido.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint8_t *dup_mem(const void *src, size_t len) {
	if (!src || len == 0) {
		return NULL;
	}
	uint8_t *p = (uint8_t *)malloc(len);
	if (p) {
		memcpy(p, src, len);
	}
	return p;
}

static void set_err(char *err, size_t errlen, const char *msg) {
	if (err && errlen) {
		snprintf(err, errlen, "%s", msg ? msg : "FIDO helper failed");
	}
}

static char *challenge_b64(const fido_request *req) {
	return fido_b64url_encode(req->challenge, req->challenge_len);
}

static int copy_client_data(const fido_request *req, const char *type, fido_response *resp) {
	char *chal = challenge_b64(req);
	char *json = fido_build_client_data_json(type, chal, req->origin);
	free(chal);
	if (!json) {
		return -1;
	}
	resp->client_data_json_len = strlen(json);
	resp->client_data_json = (uint8_t *)json;
	return 0;
}

static int try_assert_dev(fido_dev_t *dev, const fido_request *req, fido_response *resp) {
	fido_assert_t *assert = fido_assert_new();
	if (!assert) {
		return -1;
	}
	int rc = -1;
	if (fido_assert_set_rp(assert, req->rp_id) != FIDO_OK) {
		goto done;
	}
	if (fido_assert_set_clientdata(assert, resp->client_data_json,
		resp->client_data_json_len) != FIDO_OK) {
		goto done;
	}
	if (fido_assert_set_uv(assert, FIDO_OPT_TRUE) != FIDO_OK) {
		goto done;
	}
	if (fido_assert_set_up(assert, FIDO_OPT_TRUE) != FIDO_OK) {
		goto done;
	}
	for (int i = 0; i < req->allow_count; i++) {
		if (fido_assert_allow_cred(assert, req->allow[i], req->allow_len[i]) != FIDO_OK) {
			goto done;
		}
	}
	if (fido_dev_get_assert(dev, assert, NULL) != FIDO_OK) {
		goto done;
	}
	if (fido_assert_count(assert) < 1) {
		goto done;
	}
	resp->credential_id = dup_mem(fido_assert_id_ptr(assert, 0), fido_assert_id_len(assert, 0));
	resp->credential_id_len = fido_assert_id_len(assert, 0);
	resp->authenticator_data =
		dup_mem(fido_assert_authdata_raw_ptr(assert, 0), fido_assert_authdata_raw_len(assert, 0));
	resp->authenticator_data_len = fido_assert_authdata_raw_len(assert, 0);
	if (!resp->authenticator_data) {
		resp->authenticator_data =
			dup_mem(fido_assert_authdata_ptr(assert, 0), fido_assert_authdata_len(assert, 0));
		resp->authenticator_data_len = fido_assert_authdata_len(assert, 0);
	}
	resp->signature = dup_mem(fido_assert_sig_ptr(assert, 0), fido_assert_sig_len(assert, 0));
	resp->signature_len = fido_assert_sig_len(assert, 0);
	if (resp->credential_id && resp->authenticator_data && resp->signature) {
		rc = 0;
	}
done:
	fido_assert_free(&assert);
	return rc;
}

static int encode_packed_attestation(const uint8_t *authdata, size_t authdata_len,
	const uint8_t *sig, size_t sig_len, uint8_t **out, size_t *out_len) {
	/* CBOR map: fmt="packed", authData=bytes, attStmt={alg:-7, sig:bytes} */
	size_t cap = 32 + authdata_len + sig_len + 32;
	uint8_t *buf = (uint8_t *)malloc(cap);
	if (!buf) {
		return -1;
	}
	size_t n = 0;
	buf[n++] = 0xA3; /* map(3) */
	buf[n++] = 0x63; /* text(3) */
	memcpy(buf + n, "fmt", 3);
	n += 3;
	buf[n++] = 0x66; /* text(6) */
	memcpy(buf + n, "packed", 6);
	n += 6;
	buf[n++] = 0x68; /* text(8) */
	memcpy(buf + n, "authData", 8);
	n += 8;
	if (authdata_len < 24) {
		buf[n++] = (uint8_t)(0x40 + authdata_len);
	}
	else if (authdata_len <= 0xFF) {
		buf[n++] = 0x58;
		buf[n++] = (uint8_t)authdata_len;
	}
	else {
		buf[n++] = 0x59;
		buf[n++] = (uint8_t)(authdata_len >> 8);
		buf[n++] = (uint8_t)authdata_len;
	}
	memcpy(buf + n, authdata, authdata_len);
	n += authdata_len;
	buf[n++] = 0x67; /* text(7) */
	memcpy(buf + n, "attStmt", 7);
	n += 7;
	buf[n++] = 0xA2; /* map(2) */
	buf[n++] = 0x63; /* text(3) */
	memcpy(buf + n, "alg", 3);
	n += 3;
	buf[n++] = 0x26; /* -7 */
	buf[n++] = 0x63; /* text(3) */
	memcpy(buf + n, "sig", 3);
	n += 3;
	if (sig_len < 24) {
		buf[n++] = (uint8_t)(0x40 + sig_len);
	}
	else if (sig_len <= 0xFF) {
		buf[n++] = 0x58;
		buf[n++] = (uint8_t)sig_len;
	}
	else {
		buf[n++] = 0x59;
		buf[n++] = (uint8_t)(sig_len >> 8);
		buf[n++] = (uint8_t)sig_len;
	}
	memcpy(buf + n, sig, sig_len);
	n += sig_len;
	*out = buf;
	*out_len = n;
	return 0;
}

static int try_create_dev(fido_dev_t *dev, const fido_request *req, fido_response *resp) {
	fido_cred_t *cred = fido_cred_new();
	if (!cred) {
		return -1;
	}
	int rc = -1;
	if (fido_cred_set_type(cred, COSE_ES256) != FIDO_OK) {
		goto done;
	}
	if (fido_cred_set_clientdata(cred, resp->client_data_json,
		resp->client_data_json_len) != FIDO_OK) {
		goto done;
	}
	if (fido_cred_set_rp(cred, req->rp_id, req->rp_name ? req->rp_name : req->rp_id) !=
		FIDO_OK) {
		goto done;
	}
	const char *user = req->user_name ? req->user_name : "user";
	if (fido_cred_set_user(cred, req->user_id, req->user_id_len, user, NULL, NULL) !=
		FIDO_OK) {
		goto done;
	}
	if (fido_cred_set_rk(cred, FIDO_OPT_FALSE) != FIDO_OK) {
		goto done;
	}
	if (fido_cred_set_uv(cred, FIDO_OPT_TRUE) != FIDO_OK) {
		goto done;
	}
	if (fido_dev_make_cred(dev, cred, NULL) != FIDO_OK) {
		goto done;
	}
	resp->credential_id = dup_mem(fido_cred_id_ptr(cred), fido_cred_id_len(cred));
	resp->credential_id_len = fido_cred_id_len(cred);
	const uint8_t *auth = fido_cred_authdata_raw_ptr(cred);
	size_t auth_len = fido_cred_authdata_raw_len(cred);
	if (!auth) {
		auth = fido_cred_authdata_ptr(cred);
		auth_len = fido_cred_authdata_len(cred);
	}
	resp->authenticator_data = dup_mem(auth, auth_len);
	resp->authenticator_data_len = auth_len;
	resp->signature = dup_mem(fido_cred_sig_ptr(cred), fido_cred_sig_len(cred));
	resp->signature_len = fido_cred_sig_len(cred);
	if (encode_packed_attestation(auth, auth_len, fido_cred_sig_ptr(cred),
		fido_cred_sig_len(cred), &resp->attestation_object,
		&resp->attestation_object_len) != 0) {
		goto done;
	}
	if (resp->credential_id && resp->authenticator_data) {
		rc = 0;
	}
done:
	fido_cred_free(&cred);
	return rc;
}

static int with_devices(int (*fn)(fido_dev_t *, const fido_request *, fido_response *),
	const fido_request *req, fido_response *resp, char *err, size_t errlen) {
	fido_init(0);
	size_t max = 16;
	fido_dev_info_t *list = fido_dev_info_new(max);
	if (!list) {
		set_err(err, errlen, "no security key found");
		return -1;
	}
	size_t ndevs = 0;
	if (fido_dev_info_manifest(list, max, &ndevs) != FIDO_OK || ndevs == 0) {
		fido_dev_info_free(&list, max);
		set_err(err, errlen, "no security key found");
		return -1;
	}
	int rc = -1;
	for (size_t i = 0; i < ndevs; i++) {
		const fido_dev_info_t *di = fido_dev_info_ptr(list, i);
		fido_dev_t *dev = fido_dev_new();
		if (!dev) {
			continue;
		}
		if (fido_dev_open(dev, fido_dev_info_path(di)) != FIDO_OK) {
			fido_dev_free(&dev);
			continue;
		}
		if (fn(dev, req, resp) == 0) {
			rc = 0;
			fido_dev_close(dev);
			fido_dev_free(&dev);
			break;
		}
		fido_dev_close(dev);
		fido_dev_free(&dev);
	}
	fido_dev_info_free(&list, max);
	if (rc != 0) {
		set_err(err, errlen, "security key assertion or enrollment failed");
	}
	return rc;
}

int fido_platform_assert(const fido_request *req, fido_response *resp, char *err,
	size_t errlen) {
	if (copy_client_data(req, "webauthn.get", resp) != 0) {
		set_err(err, errlen, "failed to build clientDataJSON");
		return -1;
	}
	return with_devices(try_assert_dev, req, resp, err, errlen);
}

int fido_platform_create(const fido_request *req, fido_response *resp, char *err,
	size_t errlen) {
	if (copy_client_data(req, "webauthn.create", resp) != 0) {
		set_err(err, errlen, "failed to build clientDataJSON");
		return -1;
	}
	return with_devices(try_create_dev, req, resp, err, errlen);
}
