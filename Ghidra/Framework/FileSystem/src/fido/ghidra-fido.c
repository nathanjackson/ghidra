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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include "ghidra-fido-win.c"
#else
#include "ghidra-fido-libfido2.c"
#endif

int main(void) {
	char *json = NULL;
	size_t json_len = 0;
	if (fido_read_stdin(&json, &json_len) != 0 || !json || json_len == 0) {
		fido_write_error("failed to read request");
		return 1;
	}
	fido_request req;
	if (fido_parse_request(json, &req) != 0) {
		fido_wipe(json, json_len);
		free(json);
		fido_free_request(&req);
		fido_write_error("invalid request JSON");
		return 1;
	}
	fido_wipe(json, json_len);
	free(json);

	if (!req.op || !req.rp_id || !req.challenge) {
		fido_free_request(&req);
		fido_write_error("missing op, rpId, or challenge");
		return 1;
	}

	char err[FIDO_ERR_LEN];
	err[0] = 0;
	fido_response resp;
	memset(&resp, 0, sizeof(resp));
	int rc;
	if (strcmp(req.op, "create") == 0) {
		rc = fido_platform_create(&req, &resp, err, sizeof(err));
	}
	else if (strcmp(req.op, "assert") == 0) {
		rc = fido_platform_assert(&req, &resp, err, sizeof(err));
	}
	else {
		fido_free_request(&req);
		fido_write_error("unsupported op");
		return 1;
	}

	fido_free_request(&req);
	if (rc != 0) {
		fido_write_error(err[0] ? err : "FIDO helper failed");
		fido_free_response(&resp);
		return 1;
	}
	fido_write_response(&resp);
	fido_free_response(&resp);
	return 0;
}
