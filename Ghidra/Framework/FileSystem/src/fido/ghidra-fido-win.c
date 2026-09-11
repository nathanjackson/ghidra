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

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <webauthn.h>

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

static WCHAR *utf8_to_wide(const char *s) {
	if (!s) {
		return NULL;
	}
	int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
	if (n <= 0) {
		return NULL;
	}
	WCHAR *w = (WCHAR *)malloc((size_t)n * sizeof(WCHAR));
	if (!w) {
		return NULL;
	}
	MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n);
	return w;
}

static HWND helper_hwnd(int *owned) {
	HWND hwnd = CreateWindowExW(0, L"STATIC", L"ghidra-fido", 0, 0, 0, 0, 0, HWND_MESSAGE,
		NULL, GetModuleHandleW(NULL), NULL);
	if (hwnd) {
		*owned = 1;
		return hwnd;
	}
	*owned = 0;
	return GetConsoleWindow();
}

static void release_hwnd(HWND hwnd, int owned) {
	if (owned && hwnd) {
		DestroyWindow(hwnd);
	}
}

static int fill_client_data(const fido_request *req, const char *type,
	WEBAUTHN_CLIENT_DATA *cd, fido_response *resp) {
	char *chal = fido_b64url_encode(req->challenge, req->challenge_len);
	char *json = fido_build_client_data_json(type, chal, req->origin);
	free(chal);
	if (!json) {
		return -1;
	}
	resp->client_data_json_len = strlen(json);
	resp->client_data_json = (uint8_t *)json;
	memset(cd, 0, sizeof(*cd));
	cd->dwVersion = WEBAUTHN_CLIENT_DATA_CURRENT_VERSION;
	cd->cbClientDataJSON = (DWORD)resp->client_data_json_len;
	cd->pbClientDataJSON = resp->client_data_json;
	cd->pwszHashAlgId = WEBAUTHN_HASH_ALGORITHM_SHA_256;
	return 0;
}

int fido_platform_assert(const fido_request *req, fido_response *resp, char *err,
	size_t errlen) {
	WEBAUTHN_CLIENT_DATA cd;
	if (fill_client_data(req, "webauthn.get", &cd, resp) != 0) {
		set_err(err, errlen, "failed to build clientDataJSON");
		return -1;
	}
	WCHAR *rp = utf8_to_wide(req->rp_id);
	if (!rp) {
		set_err(err, errlen, "invalid rpId");
		return -1;
	}

	WEBAUTHN_CREDENTIAL allow[FIDO_MAX_ALLOW];
	memset(allow, 0, sizeof(allow));
	DWORD allow_count = 0;
	for (int i = 0; i < req->allow_count && allow_count < FIDO_MAX_ALLOW; i++) {
		allow[allow_count].dwVersion = WEBAUTHN_CREDENTIAL_CURRENT_VERSION;
		allow[allow_count].cbId = (DWORD)req->allow_len[i];
		allow[allow_count].pbId = req->allow[i];
		allow[allow_count].pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;
		allow_count++;
	}

	WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS opt;
	memset(&opt, 0, sizeof(opt));
	opt.dwVersion = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_CURRENT_VERSION;
	opt.dwTimeoutMilliseconds = req->timeout_ms > 0 ? (DWORD)req->timeout_ms : 60000;
	opt.CredentialList.cCredentials = allow_count;
	opt.CredentialList.pCredentials = allow_count ? allow : NULL;
	opt.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM;
	opt.dwUserVerificationRequirement = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED;

	WEBAUTHN_ASSERTION *assertion = NULL;
	int hwnd_owned = 0;
	HWND hwnd = helper_hwnd(&hwnd_owned);
	HRESULT hr = WebAuthNAuthenticatorGetAssertion(hwnd, rp, &cd, &opt, &assertion);
	release_hwnd(hwnd, hwnd_owned);
	free(rp);
	if (FAILED(hr) || !assertion) {
		set_err(err, errlen, "security key assertion failed");
		if (assertion) {
			WebAuthNFreeAssertion(assertion);
		}
		return -1;
	}
	resp->credential_id = dup_mem(assertion->Credential.pbId, assertion->Credential.cbId);
	resp->credential_id_len = assertion->Credential.cbId;
	resp->authenticator_data = dup_mem(assertion->pbAuthenticatorData,
		assertion->cbAuthenticatorData);
	resp->authenticator_data_len = assertion->cbAuthenticatorData;
	resp->signature = dup_mem(assertion->pbSignature, assertion->cbSignature);
	resp->signature_len = assertion->cbSignature;
	WebAuthNFreeAssertion(assertion);
	if (!resp->credential_id || !resp->authenticator_data || !resp->signature) {
		set_err(err, errlen, "security key assertion failed");
		return -1;
	}
	return 0;
}

int fido_platform_create(const fido_request *req, fido_response *resp, char *err,
	size_t errlen) {
	WEBAUTHN_CLIENT_DATA cd;
	if (fill_client_data(req, "webauthn.create", &cd, resp) != 0) {
		set_err(err, errlen, "failed to build clientDataJSON");
		return -1;
	}

	WCHAR *rp_id = utf8_to_wide(req->rp_id);
	WCHAR *rp_name = utf8_to_wide(req->rp_name ? req->rp_name : req->rp_id);
	WCHAR *user_name = utf8_to_wide(req->user_name ? req->user_name : "user");
	if (!rp_id || !rp_name || !user_name) {
		free(rp_id);
		free(rp_name);
		free(user_name);
		set_err(err, errlen, "invalid rp or user");
		return -1;
	}

	WEBAUTHN_RP_ENTITY_INFORMATION rp;
	memset(&rp, 0, sizeof(rp));
	rp.dwVersion = WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION;
	rp.pwszId = rp_id;
	rp.pwszName = rp_name;

	WEBAUTHN_USER_ENTITY_INFORMATION user;
	memset(&user, 0, sizeof(user));
	user.dwVersion = WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION;
	user.cbId = (DWORD)req->user_id_len;
	user.pbId = req->user_id;
	user.pwszName = user_name;
	user.pwszDisplayName = user_name;

	WEBAUTHN_COSE_CREDENTIAL_PARAMETER param;
	memset(&param, 0, sizeof(param));
	param.dwVersion = WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION;
	param.pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;
	param.lAlg = WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256;
	WEBAUTHN_COSE_CREDENTIAL_PARAMETERS params;
	params.cCredentialParameters = 1;
	params.pCredentialParameters = &param;

	WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS opt;
	memset(&opt, 0, sizeof(opt));
	opt.dwVersion = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_CURRENT_VERSION;
	opt.dwTimeoutMilliseconds = req->timeout_ms > 0 ? (DWORD)req->timeout_ms : 60000;
	opt.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM;
	opt.dwUserVerificationRequirement = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED;
	opt.bRequireResidentKey = FALSE;
	opt.dwAttestationConveyancePreference = WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE;

	WEBAUTHN_CREDENTIAL_ATTESTATION *att = NULL;
	int hwnd_owned = 0;
	HWND hwnd = helper_hwnd(&hwnd_owned);
	HRESULT hr = WebAuthNAuthenticatorMakeCredential(hwnd, &rp, &user, &params, &cd, &opt,
		&att);
	release_hwnd(hwnd, hwnd_owned);
	free(rp_id);
	free(rp_name);
	free(user_name);
	if (FAILED(hr) || !att) {
		set_err(err, errlen, "security key enrollment failed");
		if (att) {
			WebAuthNFreeCredentialAttestation(att);
		}
		return -1;
	}
	resp->credential_id = dup_mem(att->cbCredentialId ? att->pbCredentialId : NULL,
		att->cbCredentialId);
	resp->credential_id_len = att->cbCredentialId;
	resp->authenticator_data = dup_mem(att->pbAuthenticatorData, att->cbAuthenticatorData);
	resp->authenticator_data_len = att->cbAuthenticatorData;
	if (fido_encode_none_attestation(att->pbAuthenticatorData, att->cbAuthenticatorData,
		&resp->attestation_object, &resp->attestation_object_len) != 0) {
		WebAuthNFreeCredentialAttestation(att);
		set_err(err, errlen, "security key enrollment failed");
		return -1;
	}
	WebAuthNFreeCredentialAttestation(att);
	if (!resp->credential_id || !resp->attestation_object) {
		set_err(err, errlen, "security key enrollment failed");
		return -1;
	}
	return 0;
}
