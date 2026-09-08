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
/*
 * CTAP/HID backend for Linux, macOS, and BSD. AuthenticationServices cannot
 * be used from Ghidra's unsigned helper (no application identifier).
 */
#include "ghidra-fido-json.h"

#include <fido.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

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

static void wipe(void *p, size_t n) {
	volatile unsigned char *v = (volatile unsigned char *)p;
	if (!v) {
		return;
	}
	while (n--) {
		*v++ = 0;
	}
}

static void wipe_pin(char *pin) {
	if (!pin) {
		return;
	}
	wipe(pin, strlen(pin));
	free(pin);
}

static void set_err(char *err, size_t errlen, const char *msg) {
	if (err && errlen) {
		snprintf(err, errlen, "%s", msg ? msg : "FIDO helper failed");
	}
}

static void set_fido_err(char *err, size_t errlen, int r) {
	switch (r) {
		case FIDO_ERR_PIN_REQUIRED:
			set_err(err, errlen, "security key PIN required");
			break;
		case FIDO_ERR_PIN_INVALID:
			set_err(err, errlen, "security key PIN invalid");
			break;
		case FIDO_ERR_PIN_AUTH_BLOCKED:
		case FIDO_ERR_UV_BLOCKED:
			set_err(err, errlen, "security key PIN or UV blocked");
			break;
		case FIDO_ERR_TIMEOUT:
			set_err(err, errlen, "FIDO helper timed out");
			break;
		default:
			if (err && errlen) {
				snprintf(err, errlen, "security key assertion or enrollment failed (%s)",
					fido_strerr(r));
			}
			break;
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

/* libfido2 does not prompt; PIN must come from a real TTY. */
static char *read_pin_tty(void) {
	int fd = open("/dev/tty", O_RDWR | O_NOCTTY);
	if (fd < 0) {
		return NULL;
	}
	FILE *tty = fdopen(fd, "r+");
	if (!tty) {
		close(fd);
		return NULL;
	}
	struct termios oldt;
	struct termios newt;
	int have_term = tcgetattr(fd, &oldt) == 0;
	if (have_term) {
		newt = oldt;
		newt.c_lflag &= (tcflag_t) ~(ECHO | ECHOE | ECHOK | ECHONL);
		tcsetattr(fd, TCSANOW, &newt);
	}
	fputs("Enter security key PIN: ", tty);
	fflush(tty);
	char buf[64];
	char *got = fgets(buf, (int)sizeof(buf), tty);
	if (have_term) {
		tcsetattr(fd, TCSANOW, &oldt);
	}
	fputc('\n', tty);
	fflush(tty);
	fclose(tty);
	if (!got) {
		return NULL;
	}
	size_t n = strlen(buf);
	while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r')) {
		buf[--n] = 0;
	}
	if (n < 4 || n > 63) {
		wipe(buf, sizeof(buf));
		return NULL;
	}
	char *pin = (char *)malloc(n + 1);
	if (!pin) {
		wipe(buf, sizeof(buf));
		return NULL;
	}
	memcpy(pin, buf, n + 1);
	wipe(buf, sizeof(buf));
	return pin;
}

static int encode_cbor_bstr(uint8_t *buf, size_t *n, const uint8_t *data, size_t len) {
	if (len < 24) {
		buf[(*n)++] = (uint8_t)(0x40 + len);
	}
	else if (len <= 0xFF) {
		buf[(*n)++] = 0x58;
		buf[(*n)++] = (uint8_t)len;
	}
	else {
		buf[(*n)++] = 0x59;
		buf[(*n)++] = (uint8_t)(len >> 8);
		buf[(*n)++] = (uint8_t)len;
	}
	if (data != NULL && len > 0) {
		memcpy(buf + *n, data, len);
		*n += len;
	}
	return 0;
}

/* Server accepts fmt=none with empty attStmt; never wrap a batch-attestation sig as packed. */
static int encode_none_attestation(const uint8_t *authdata, size_t authdata_len, uint8_t **out,
	size_t *out_len) {
	size_t cap = 32 + authdata_len;
	uint8_t *buf = (uint8_t *)malloc(cap);
	if (!buf) {
		return -1;
	}
	size_t n = 0;
	buf[n++] = 0xA3; /* map(3) */
	buf[n++] = 0x63;
	memcpy(buf + n, "fmt", 3);
	n += 3;
	buf[n++] = 0x64;
	memcpy(buf + n, "none", 4);
	n += 4;
	buf[n++] = 0x68;
	memcpy(buf + n, "authData", 8);
	n += 8;
	encode_cbor_bstr(buf, &n, authdata, authdata_len);
	buf[n++] = 0x67;
	memcpy(buf + n, "attStmt", 7);
	n += 7;
	buf[n++] = 0xA0; /* map(0) */
	*out = buf;
	*out_len = n;
	return 0;
}

static int try_assert_dev(fido_dev_t *dev, const fido_request *req, fido_response *resp,
	char *err, size_t errlen) {
	fido_assert_t *assert = fido_assert_new();
	if (!assert) {
		set_err(err, errlen, "security key assertion or enrollment failed");
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
	const char *json_pin = (req->pin && req->pin[0]) ? req->pin : NULL;
	char *pin = NULL;
	int pin_owned = 0;
	if (json_pin) {
		pin = (char *)json_pin;
	}
	else if (fido_dev_has_pin(dev)) {
		pin = read_pin_tty();
		pin_owned = 1;
		if (!pin) {
			set_err(err, errlen, "security key PIN required");
			goto done;
		}
	}
	int r = fido_dev_get_assert(dev, assert, pin);
	if ((r == FIDO_ERR_PIN_REQUIRED || r == FIDO_ERR_PIN_AUTH_INVALID) && !json_pin) {
		if (pin_owned) {
			wipe_pin(pin);
			pin_owned = 0;
		}
		pin = read_pin_tty();
		pin_owned = 1;
		if (!pin) {
			set_err(err, errlen, "security key PIN required");
			goto done;
		}
		r = fido_dev_get_assert(dev, assert, pin);
	}
	if (pin_owned) {
		wipe_pin(pin);
	}
	pin = NULL;
	if (r != FIDO_OK) {
		set_fido_err(err, errlen, r);
		goto done;
	}
	if (fido_assert_count(assert) < 1) {
		set_err(err, errlen, "security key assertion or enrollment failed");
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
	else {
		set_err(err, errlen, "security key assertion or enrollment failed");
	}
done:
	fido_assert_free(&assert);
	return rc;
}

static int try_create_dev(fido_dev_t *dev, const fido_request *req, fido_response *resp,
	char *err, size_t errlen) {
	fido_cred_t *cred = fido_cred_new();
	if (!cred) {
		set_err(err, errlen, "security key assertion or enrollment failed");
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
	/* Prefer none so the authenticator does not attach packed+x5c. */
	(void) fido_cred_set_fmt(cred, "none");
	const char *json_pin = (req->pin && req->pin[0]) ? req->pin : NULL;
	char *pin = NULL;
	int pin_owned = 0;
	if (json_pin) {
		pin = (char *)json_pin;
	}
	else if (fido_dev_has_pin(dev)) {
		pin = read_pin_tty();
		pin_owned = 1;
		if (!pin) {
			set_err(err, errlen, "security key PIN required");
			goto done;
		}
	}
	int r = fido_dev_make_cred(dev, cred, pin);
	if ((r == FIDO_ERR_PIN_REQUIRED || r == FIDO_ERR_PIN_AUTH_INVALID) && !json_pin) {
		if (pin_owned) {
			wipe_pin(pin);
			pin_owned = 0;
		}
		pin = read_pin_tty();
		pin_owned = 1;
		if (!pin) {
			set_err(err, errlen, "security key PIN required");
			goto done;
		}
		r = fido_dev_make_cred(dev, cred, pin);
	}
	if (pin_owned) {
		wipe_pin(pin);
	}
	pin = NULL;
	if (r != FIDO_OK) {
		set_fido_err(err, errlen, r);
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
	if (encode_none_attestation(auth, auth_len, &resp->attestation_object,
		&resp->attestation_object_len) != 0) {
		set_err(err, errlen, "security key assertion or enrollment failed");
		goto done;
	}
	if (resp->credential_id && resp->authenticator_data && resp->attestation_object) {
		rc = 0;
	}
	else {
		set_err(err, errlen, "security key assertion or enrollment failed");
	}
done:
	fido_cred_free(&cred);
	return rc;
}

static int with_devices(
	int (*fn)(fido_dev_t *, const fido_request *, fido_response *, char *, size_t),
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
	char last[FIDO_ERR_LEN];
	last[0] = 0;
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
		if (req->timeout_ms > 0) {
			(void) fido_dev_set_timeout(dev, req->timeout_ms);
		}
		last[0] = 0;
		if (fn(dev, req, resp, last, sizeof(last)) == 0) {
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
		set_err(err, errlen, last[0] ? last : "security key assertion or enrollment failed");
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
