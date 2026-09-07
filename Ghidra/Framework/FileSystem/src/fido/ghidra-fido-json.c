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

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define STDIN_MAX (256 * 1024)

static const char B64URL[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static void skip_ws(const char **p) {
	while (**p && isspace((unsigned char)**p)) {
		(*p)++;
	}
}

static int parse_string(const char **p, char **out) {
	const char *s = *p;
	if (*s != '"') {
		return -1;
	}
	s++;
	size_t cap = 32;
	size_t n = 0;
	char *buf = (char *)malloc(cap);
	if (!buf) {
		return -1;
	}
	while (*s && *s != '"') {
		char c = *s++;
		if (c == '\\') {
			if (!*s) {
				free(buf);
				return -1;
			}
			c = *s++;
			switch (c) {
				case '"':
				case '\\':
				case '/':
					break;
				case 'b':
					c = '\b';
					break;
				case 'f':
					c = '\f';
					break;
				case 'n':
					c = '\n';
					break;
				case 'r':
					c = '\r';
					break;
				case 't':
					c = '\t';
					break;
				case 'u':
					/* keep a '?' rather than decoding UTF-16 escapes */
					s += (strlen(s) >= 4) ? 4 : strlen(s);
					c = '?';
					break;
				default:
					break;
			}
		}
		if (n + 1 >= cap) {
			cap *= 2;
			char *nb = (char *)realloc(buf, cap);
			if (!nb) {
				free(buf);
				return -1;
			}
			buf = nb;
		}
		buf[n++] = c;
	}
	if (*s != '"') {
		free(buf);
		return -1;
	}
	s++;
	buf[n] = 0;
	*out = buf;
	*p = s;
	return 0;
}

static int parse_number(const char **p, int *out) {
	char *end = NULL;
	long v = strtol(*p, &end, 10);
	if (end == *p) {
		return -1;
	}
	*out = (int)v;
	*p = end;
	return 0;
}

static int parse_bool(const char **p, int *out) {
	if (strncmp(*p, "true", 4) == 0) {
		*out = 1;
		*p += 4;
		return 0;
	}
	if (strncmp(*p, "false", 5) == 0) {
		*out = 0;
		*p += 5;
		return 0;
	}
	return -1;
}

static int skip_value(const char **p);

static int skip_object_or_array(const char **p, char open_c, char close_c) {
	if (**p != open_c) {
		return -1;
	}
	(*p)++;
	skip_ws(p);
	if (**p == close_c) {
		(*p)++;
		return 0;
	}
	while (**p) {
		if (skip_value(p) != 0) {
			return -1;
		}
		skip_ws(p);
		if (**p == ',') {
			(*p)++;
			skip_ws(p);
			continue;
		}
		if (**p == close_c) {
			(*p)++;
			return 0;
		}
		return -1;
	}
	return -1;
}

static int skip_value(const char **p) {
	skip_ws(p);
	if (**p == '"') {
		char *tmp = NULL;
		if (parse_string(p, &tmp) != 0) {
			return -1;
		}
		free(tmp);
		return 0;
	}
	if (**p == '{') {
		const char *s = *p;
		s++;
		skip_ws(&s);
		if (*s == '}') {
			s++;
			*p = s;
			return 0;
		}
		while (*s) {
			char *key = NULL;
			if (parse_string(&s, &key) != 0) {
				return -1;
			}
			free(key);
			skip_ws(&s);
			if (*s != ':') {
				return -1;
			}
			s++;
			*p = s;
			if (skip_value(p) != 0) {
				return -1;
			}
			s = *p;
			skip_ws(&s);
			if (*s == ',') {
				s++;
				skip_ws(&s);
				continue;
			}
			if (*s == '}') {
				s++;
				*p = s;
				return 0;
			}
			return -1;
		}
		return -1;
	}
	if (**p == '[') {
		return skip_object_or_array(p, '[', ']');
	}
	if (strncmp(*p, "true", 4) == 0) {
		*p += 4;
		return 0;
	}
	if (strncmp(*p, "false", 5) == 0) {
		*p += 5;
		return 0;
	}
	if (strncmp(*p, "null", 4) == 0) {
		*p += 4;
		return 0;
	}
	if (**p == '-' || isdigit((unsigned char)**p)) {
		int dummy;
		return parse_number(p, &dummy);
	}
	return -1;
}

static int parse_string_array(const char **p, fido_request *req) {
	skip_ws(p);
	if (**p != '[') {
		return -1;
	}
	(*p)++;
	skip_ws(p);
	if (**p == ']') {
		(*p)++;
		return 0;
	}
	while (**p && req->allow_count < FIDO_MAX_ALLOW) {
		char *s = NULL;
		skip_ws(p);
		if (parse_string(p, &s) != 0) {
			return -1;
		}
		if (fido_b64url_decode(s, &req->allow[req->allow_count],
			&req->allow_len[req->allow_count]) == 0) {
			req->allow_count++;
		}
		free(s);
		skip_ws(p);
		if (**p == ',') {
			(*p)++;
			continue;
		}
		if (**p == ']') {
			(*p)++;
			return 0;
		}
		return -1;
	}
	return skip_object_or_array(p, '[', ']');
}

int fido_read_stdin(char **out, size_t *out_len) {
	size_t cap = 4096;
	size_t n = 0;
	char *buf = (char *)malloc(cap);
	if (!buf) {
		return -1;
	}
	int c;
	while ((c = fgetc(stdin)) != EOF) {
		if (n + 1 >= cap) {
			if (cap >= STDIN_MAX) {
				free(buf);
				return -1;
			}
			cap *= 2;
			if (cap > STDIN_MAX) {
				cap = STDIN_MAX;
			}
			char *nb = (char *)realloc(buf, cap);
			if (!nb) {
				free(buf);
				return -1;
			}
			buf = nb;
		}
		buf[n++] = (char)c;
	}
	buf[n] = 0;
	*out = buf;
	*out_len = n;
	return 0;
}

int fido_parse_request(const char *json, fido_request *req) {
	memset(req, 0, sizeof(*req));
	const char *p = json;
	skip_ws(&p);
	if (*p != '{') {
		return -1;
	}
	p++;
	skip_ws(&p);
	if (*p == '}') {
		return 0;
	}
	while (*p) {
		char *key = NULL;
		skip_ws(&p);
		if (parse_string(&p, &key) != 0) {
			return -1;
		}
		skip_ws(&p);
		if (*p != ':') {
			free(key);
			return -1;
		}
		p++;
		skip_ws(&p);
		if (strcmp(key, "op") == 0) {
			if (parse_string(&p, &req->op) != 0) {
				free(key);
				return -1;
			}
		}
		else if (strcmp(key, "rpId") == 0) {
			if (parse_string(&p, &req->rp_id) != 0) {
				free(key);
				return -1;
			}
		}
		else if (strcmp(key, "rpName") == 0) {
			if (parse_string(&p, &req->rp_name) != 0) {
				free(key);
				return -1;
			}
		}
		else if (strcmp(key, "origin") == 0) {
			if (parse_string(&p, &req->origin) != 0) {
				free(key);
				return -1;
			}
		}
		else if (strcmp(key, "challenge") == 0) {
			char *b64 = NULL;
			if (parse_string(&p, &b64) != 0) {
				free(key);
				return -1;
			}
			fido_b64url_decode(b64, &req->challenge, &req->challenge_len);
			free(b64);
		}
		else if (strcmp(key, "timeoutMs") == 0) {
			if (parse_number(&p, &req->timeout_ms) != 0) {
				free(key);
				return -1;
			}
		}
		else if (strcmp(key, "userName") == 0) {
			if (parse_string(&p, &req->user_name) != 0) {
				free(key);
				return -1;
			}
		}
		else if (strcmp(key, "userId") == 0) {
			char *b64 = NULL;
			if (parse_string(&p, &b64) != 0) {
				free(key);
				return -1;
			}
			fido_b64url_decode(b64, &req->user_id, &req->user_id_len);
			free(b64);
		}
		else if (strcmp(key, "allowCredentials") == 0) {
			if (parse_string_array(&p, req) != 0) {
				free(key);
				return -1;
			}
		}
		else if (strcmp(key, "residentKey") == 0) {
			if (parse_bool(&p, &req->resident_key) != 0) {
				free(key);
				return -1;
			}
		}
		else if (strcmp(key, "userVerification") == 0) {
			if (parse_string(&p, &req->user_verification) != 0) {
				free(key);
				return -1;
			}
		}
		else if (strcmp(key, "authenticatorAttachment") == 0) {
			if (parse_string(&p, &req->attachment) != 0) {
				free(key);
				return -1;
			}
		}
		else if (strcmp(key, "pin") == 0) {
			if (parse_string(&p, &req->pin) != 0) {
				free(key);
				return -1;
			}
		}
		else {
			if (skip_value(&p) != 0) {
				free(key);
				return -1;
			}
		}
		free(key);
		skip_ws(&p);
		if (*p == ',') {
			p++;
			continue;
		}
		if (*p == '}') {
			return 0;
		}
		return -1;
	}
	return -1;
}

void fido_wipe(void *p, size_t n) {
	volatile unsigned char *v = (volatile unsigned char *)p;
	if (!v) {
		return;
	}
	while (n--) {
		*v++ = 0;
	}
}

void fido_free_request(fido_request *req) {
	if (!req) {
		return;
	}
	free(req->op);
	free(req->rp_id);
	free(req->rp_name);
	free(req->origin);
	free(req->challenge);
	free(req->user_name);
	free(req->user_id);
	free(req->user_verification);
	free(req->attachment);
	if (req->pin) {
		fido_wipe(req->pin, strlen(req->pin));
		free(req->pin);
	}
	for (int i = 0; i < req->allow_count; i++) {
		free(req->allow[i]);
	}
	memset(req, 0, sizeof(*req));
}

void fido_free_response(fido_response *resp) {
	if (!resp) {
		return;
	}
	free(resp->credential_id);
	free(resp->authenticator_data);
	free(resp->client_data_json);
	free(resp->signature);
	free(resp->attestation_object);
	memset(resp, 0, sizeof(*resp));
}

static void json_escape_write(FILE *f, const char *s) {
	fputc('"', f);
	if (!s) {
		fputc('"', f);
		return;
	}
	for (; *s; s++) {
		unsigned char c = (unsigned char)*s;
		switch (c) {
			case '"':
				fputs("\\\"", f);
				break;
			case '\\':
				fputs("\\\\", f);
				break;
			case '\n':
				fputs("\\n", f);
				break;
			case '\r':
				fputs("\\r", f);
				break;
			case '\t':
				fputs("\\t", f);
				break;
			default:
				if (c < 0x20) {
					fprintf(f, "\\u%04x", c);
				}
				else {
					fputc(c, f);
				}
				break;
		}
	}
	fputc('"', f);
}

static void write_b64_field(FILE *f, const char *name, const uint8_t *data, size_t len,
	int *first) {
	if (!data || len == 0) {
		return;
	}
	char *b64 = fido_b64url_encode(data, len);
	if (!b64) {
		return;
	}
	if (!*first) {
		fputc(',', f);
	}
	*first = 0;
	fprintf(f, "\"%s\":", name);
	json_escape_write(f, b64);
	free(b64);
}

int fido_write_response(const fido_response *resp) {
	int first = 1;
	fputc('{', stdout);
	write_b64_field(stdout, "credentialId", resp->credential_id, resp->credential_id_len,
		&first);
	write_b64_field(stdout, "authenticatorData", resp->authenticator_data,
		resp->authenticator_data_len, &first);
	write_b64_field(stdout, "clientDataJSON", resp->client_data_json,
		resp->client_data_json_len, &first);
	write_b64_field(stdout, "signature", resp->signature, resp->signature_len, &first);
	write_b64_field(stdout, "attestationObject", resp->attestation_object,
		resp->attestation_object_len, &first);
	fputc('}', stdout);
	fputc('\n', stdout);
	fflush(stdout);
	return 0;
}

int fido_write_error(const char *msg) {
	fputs("{\"error\":", stdout);
	json_escape_write(stdout, msg ? msg : "FIDO helper failed");
	fputs("}\n", stdout);
	fflush(stdout);
	return 0;
}

char *fido_build_client_data_json(const char *type, const char *challenge_b64,
	const char *origin) {
	const char *t = type ? type : "webauthn.get";
	const char *c = challenge_b64 ? challenge_b64 : "";
	const char *o = origin ? origin : "";
	size_t len = 64 + strlen(t) + strlen(c) + strlen(o);
	char *buf = (char *)malloc(len);
	if (!buf) {
		return NULL;
	}
	snprintf(buf, len,
		"{\"type\":\"%s\",\"challenge\":\"%s\",\"origin\":\"%s\",\"crossOrigin\":false}", t, c,
		o);
	return buf;
}

char *fido_b64url_encode(const uint8_t *data, size_t len) {
	if (!data) {
		char *empty = (char *)calloc(1, 1);
		return empty;
	}
	size_t out_len = 4 * ((len + 2) / 3) + 1;
	char *out = (char *)malloc(out_len);
	if (!out) {
		return NULL;
	}
	size_t i = 0, o = 0;
	while (i + 3 <= len) {
		unsigned v = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2];
		out[o++] = B64URL[(v >> 18) & 63];
		out[o++] = B64URL[(v >> 12) & 63];
		out[o++] = B64URL[(v >> 6) & 63];
		out[o++] = B64URL[v & 63];
		i += 3;
	}
	if (i < len) {
		unsigned v = data[i] << 16;
		if (i + 1 < len) {
			v |= data[i + 1] << 8;
		}
		out[o++] = B64URL[(v >> 18) & 63];
		out[o++] = B64URL[(v >> 12) & 63];
		if (i + 1 < len) {
			out[o++] = B64URL[(v >> 6) & 63];
		}
	}
	out[o] = 0;
	return out;
}

static int b64url_val(int c) {
	if (c >= 'A' && c <= 'Z') {
		return c - 'A';
	}
	if (c >= 'a' && c <= 'z') {
		return c - 'a' + 26;
	}
	if (c >= '0' && c <= '9') {
		return c - '0' + 52;
	}
	if (c == '-' || c == '+') {
		return 62;
	}
	if (c == '_' || c == '/') {
		return 63;
	}
	return -1;
}

int fido_b64url_decode(const char *s, uint8_t **out, size_t *out_len) {
	if (!s) {
		return -1;
	}
	size_t n = strlen(s);
	while (n > 0 && s[n - 1] == '=') {
		n--;
	}
	if (n > (FIDO_MAX_BLOB * 4) / 3 + 8) {
		return -1;
	}
	size_t cap = (n * 3) / 4 + 2;
	uint8_t *buf = (uint8_t *)malloc(cap);
	if (!buf) {
		return -1;
	}
	size_t o = 0;
	int val = 0;
	int bits = 0;
	for (size_t i = 0; i < n; i++) {
		int d = b64url_val((unsigned char)s[i]);
		if (d < 0) {
			free(buf);
			return -1;
		}
		val = (val << 6) | d;
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			buf[o++] = (uint8_t)((val >> bits) & 0xff);
		}
	}
	if (o > FIDO_MAX_BLOB) {
		free(buf);
		return -1;
	}
	*out = buf;
	*out_len = o;
	return 0;
}
