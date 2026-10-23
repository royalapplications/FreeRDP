/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Certificate Handling
 *
 * Copyright 2011 Jiten Pathy
 * Copyright 2011-2012 Marc-Andre Moreau <marcandre.moreau@gmail.com>
 * Copyright 2023 Armin Novak <anovak@thincast.com>
 * Copyright 2023 Thincast Technologies GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <freerdp/config.h>

#include <winpr/assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <winpr/crypto.h>
#include <winpr/crt.h>
#include <winpr/file.h>
#include <winpr/path.h>
#include <winpr/print.h>

#include <freerdp/settings.h>

#include <freerdp/crypto/crypto.h>
#include <freerdp/crypto/certificate_store.h>
#include <freerdp/log.h>
#include "certificate_store.h"

struct rdp_certificate_store
{
	char* certs_path;
	char* server_path;
	BOOL hash_hostnames;
};

static const char certificate_store_dir[] = "certs";
static const char certificate_server_dir[] = "server";

static char* freerdp_certificate_store_hash_host(const char* host, UINT16 port)
{
	BYTE digest[WINPR_SHA256_DIGEST_LENGTH] = WINPR_C_ARRAY_INIT;
	char hex[2 * sizeof(digest) + 1] = WINPR_C_ARRAY_INIT;
	char name[sizeof(hex) + sizeof("_65535.pem")] = WINPR_C_ARRAY_INIT;
	if (!host)
		return nullptr;
	char* normalized = _strdup(host);
	if (!normalized)
		return nullptr;
	const size_t length = strlen(normalized);
	for (size_t x = 0; x < length; x++)
		normalized[x] = (char)tolower((unsigned char)normalized[x]);
	/* Preserve punctuation so IPv6 addresses cannot alias dotted DNS names. */
	const BOOL rc = winpr_Digest(WINPR_MD_SHA256, normalized, length, digest, sizeof(digest));
	free(normalized);
	if (!rc || !winpr_BinToHexStringBuffer(digest, sizeof(digest), hex, sizeof(hex), FALSE))
		return nullptr;
	(void)snprintf(name, sizeof(name), "%s_%" PRIu16 ".pem", hex, port);
	return _strdup(name);
}

static char* freerdp_certificate_store_file_path(const rdpCertificateStore* store, const char* hash)
{
	const char* hosts = freerdp_certificate_store_get_hosts_path(store);

	if (!hosts || !hash)
		return nullptr;

	return GetCombinedPath(hosts, hash);
}

freerdp_certificate_store_result
freerdp_certificate_store_contains_data(rdpCertificateStore* store, const rdpCertificateData* data)
{
	freerdp_certificate_store_result rc = CERT_STORE_NOT_FOUND;
	const char* host = freerdp_certificate_data_get_host(data);
	const UINT16 port = freerdp_certificate_data_get_port(data);

	rdpCertificateData* loaded = freerdp_certificate_store_load_data(store, host, port);
	if (!loaded)
		goto fail;

	rc = freerdp_certificate_data_equal(data, loaded) ? CERT_STORE_MATCH : CERT_STORE_MISMATCH;

fail:
	freerdp_certificate_data_free(loaded);
	return rc;
}

BOOL freerdp_certificate_store_remove_data(rdpCertificateStore* store,
                                           const rdpCertificateData* data)
{
	BOOL rc = TRUE;

	WINPR_ASSERT(store);

	if (!data)
		return FALSE;
	char* path = freerdp_certificate_store_get_cert_path(
	    store, freerdp_certificate_data_get_host(data), freerdp_certificate_data_get_port(data));

	if (!path)
		return FALSE;

	if (winpr_PathFileExists(path))
		rc = winpr_DeleteFile(path);
	free(path);
	return rc;
}

BOOL freerdp_certificate_store_save_data(rdpCertificateStore* store, const rdpCertificateData* data)
{
	BOOL rc = FALSE;
	const char* base = freerdp_certificate_store_get_hosts_path(store);
	char* path = freerdp_certificate_store_get_cert_path(
	    store, freerdp_certificate_data_get_host(data), freerdp_certificate_data_get_port(data));
	FILE* fp = nullptr;

	if (!path)
		goto fail;

	if (!winpr_PathFileExists(base))
	{
		if (!winpr_PathMakePath(base, nullptr))
			goto fail;
	}

	fp = winpr_fopen(path, "w");
	if (!fp)
		goto fail;

	(void)fprintf(fp, "%s", freerdp_certificate_data_get_pem_ex(data, FALSE));

	rc = TRUE;
fail:
	if (fp)
		(void)fclose(fp);
	free(path);
	return rc;
}

rdpCertificateData* freerdp_certificate_store_load_data(rdpCertificateStore* store,
                                                        const char* host, UINT16 port)
{
	char* path = nullptr;
	rdpCertificateData* data = nullptr;

	WINPR_ASSERT(store);

	path = freerdp_certificate_store_get_cert_path(store, host, port);
	if (!path)
		goto fail;

	data = freerdp_certificate_data_new_from_file(host, port, path);

fail:
	free(path);
	return data;
}

rdpCertificateStore* freerdp_certificate_store_new(const rdpSettings* settings)
{
	return freerdp_certificate_store_new_ex(settings, nullptr);
}

rdpCertificateStore* freerdp_certificate_store_new_ex(const rdpSettings* settings,
                                                      const char* subpath)
{
	rdpCertificateStore* store = (rdpCertificateStore*)calloc(1, sizeof(rdpCertificateStore));
	char* path = nullptr;

	if (!store)
		return nullptr;

	const char* base = freerdp_settings_get_string(settings, FreeRDP_ConfigPath);
	if (!base)
		goto fail;

	path = subpath ? GetCombinedPath(base, subpath) : _strdup(base);
	if (!path)
		goto fail;
	store->certs_path = GetCombinedPath(path, certificate_store_dir);
	/* A separate directory prevents old, ambiguous filenames from becoming hashed pins. */
	store->server_path = GetCombinedPath(path, subpath ? "server-sha256" : certificate_server_dir);
	store->hash_hostnames = subpath != nullptr;
	if (!store->certs_path || !store->server_path)
		goto fail;

	free(path);
	return store;

fail:
	free(path);
	WINPR_PRAGMA_DIAG_PUSH
	WINPR_PRAGMA_DIAG_IGNORED_MISMATCHED_DEALLOC
	freerdp_certificate_store_free(store);
	WINPR_PRAGMA_DIAG_POP
	return nullptr;
}

void freerdp_certificate_store_free(rdpCertificateStore* store)
{
	if (!store)
		return;

	free(store->certs_path);
	free(store->server_path);
	free(store);
}

const char* freerdp_certificate_store_get_certs_path(const rdpCertificateStore* store)
{
	WINPR_ASSERT(store);
	return store->certs_path;
}

const char* freerdp_certificate_store_get_hosts_path(const rdpCertificateStore* store)
{
	WINPR_ASSERT(store);
	return store->server_path;
}

char* freerdp_certificate_store_get_cert_path(const rdpCertificateStore* store, const char* host,
                                              UINT16 port)
{
	WINPR_ASSERT(store);

	char* hash = store->hash_hostnames ? freerdp_certificate_store_hash_host(host, port)
	                                   : freerdp_certificate_data_hash(host, port);
	if (!hash)
		return nullptr;
	char* path = freerdp_certificate_store_file_path(store, hash);
	free(hash);
	return path;
}
