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
#ifndef GHIDRA_FIDO_JSON_H
#define GHIDRA_FIDO_JSON_H

#include <stddef.h>
#include <stdint.h>

#define FIDO_MAX_ALLOW 64
#define FIDO_MAX_BLOB 8192
#define FIDO_ERR_LEN 256

typedef struct {
	char *op;
	char *rp_id;
	char *rp_name;
	char *origin;
	uint8_t *challenge;
	size_t challenge_len;
	int timeout_ms;
	char *user_name;
	uint8_t *user_id;
	size_t user_id_len;
	uint8_t *allow[FIDO_MAX_ALLOW];
	size_t allow_len[FIDO_MAX_ALLOW];
	int allow_count;
	int resident_key;
	char *user_verification;
	char *attachment;
	char *pin;
} fido_request;

typedef struct {
	uint8_t *credential_id;
	size_t credential_id_len;
	uint8_t *authenticator_data;
	size_t authenticator_data_len;
	uint8_t *client_data_json;
	size_t client_data_json_len;
	uint8_t *signature;
	size_t signature_len;
	uint8_t *attestation_object;
	size_t attestation_object_len;
} fido_response;

int fido_read_stdin(char **out, size_t *out_len);
int fido_parse_request(const char *json, fido_request *req);
void fido_free_request(fido_request *req);
void fido_free_response(fido_response *resp);
int fido_write_response(const fido_response *resp);
int fido_write_error(const char *msg);
char *fido_build_client_data_json(const char *type, const char *challenge_b64,
	const char *origin);
char *fido_b64url_encode(const uint8_t *data, size_t len);
int fido_b64url_decode(const char *s, uint8_t **out, size_t *out_len);
void fido_wipe(void *p, size_t n);

int fido_platform_assert(const fido_request *req, fido_response *resp, char *err,
	size_t errlen);
int fido_platform_create(const fido_request *req, fido_response *resp, char *err,
	size_t errlen);

#endif
