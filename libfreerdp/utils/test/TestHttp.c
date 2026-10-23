/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * HTTPS certificate verification tests
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <signal.h>
#endif

#include <winpr/crt.h>
#include <winpr/environment.h>
#include <winpr/file.h>
#include <winpr/path.h>
#include <winpr/synch.h>
#include <winpr/thread.h>
#include <winpr/winsock.h>

#include <freerdp/freerdp.h>
#include <freerdp/utils/aad.h>
#include <freerdp/utils/http.h>
#include <freerdp/crypto/certificate_store.h>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include "../../crypto/certificate_store.h"

typedef struct
{
	BIO* listener;
	int socket;
	BOOL received;
	BOOL replied;
	const char* body;
} HttpTestServer;

typedef struct
{
	rdpContext context;
	X509* ca;
	X509* certificate;
	const char* hostname;
	UINT16 port;
	DWORD flags;
	int decision;
	size_t calls;
	BOOL invalid;
} HttpTestContext;

typedef struct
{
	const char* name;
	const char* hostname;
	BOOL mismatch;
	BOOL trusted;
	BOOL external;
	BOOL callback;
	int decision;
	BOOL legacy;
	BOOL discovery;
	BOOL success;
	size_t calls;
	BOOL strict;
	BOOL storeFailure;
} HttpTestCase;

static BOOL test_remove_pin(const char* configPath, const char* hostname, UINT16 port)
{
	BOOL ret = FALSE;
	rdpSettings* settings = freerdp_settings_new(0);
	rdpCertificateStore* store = nullptr;
	char* path = nullptr;
	char* base = GetCombinedPath(configPath, "https");
	if (!settings || !base ||
	    !freerdp_settings_set_string(settings, FreeRDP_ConfigPath, configPath))
		goto out;
	store = freerdp_certificate_store_new_ex(settings, "https");
	if (!store)
		goto out;
	path = freerdp_certificate_store_get_cert_path(store, hostname, port);
	if (!path)
		goto out;
	if (winpr_PathFileExists(path) && !DeleteFileA(path))
		goto out;
	/* These only succeed when the directories are empty; never remove unrelated pins. */
	(void)RemoveDirectoryA(freerdp_certificate_store_get_hosts_path(store));
	(void)RemoveDirectoryA(base);
	ret = TRUE;
out:
	free(path);
	free(base);
	freerdp_certificate_store_free(store);
	freerdp_settings_free(settings);
	return ret;
}

static rdpCertificateData* test_certificate_data_new(const char* host, UINT16 port, X509* cert)
{
	rdpCertificateData* data = nullptr;
	BIO* bio = BIO_new(BIO_s_mem());
	if (!bio)
		return nullptr;
	if ((PEM_write_bio_X509(bio, cert) == 1) && (BIO_write(bio, "", 1) == 1))
	{
		char* pem = nullptr;
		const long length = BIO_get_mem_data(bio, &pem);
		if (length > 1)
			data = freerdp_certificate_data_new_from_pem(host, port, pem, (size_t)length - 1);
	}
	BIO_free(bio);
	return data;
}

static BOOL test_persisted_endpoint_identity(X509* cert, X509* replacement, const char* configPath)
{
	BOOL ret = FALSE;
	const char* ipv6 = "2001:db8:1:2:3:4:abcd:cafe";
	const char* dns = "2001.db8.1.2.3.4.abcd.cafe";
	rdpSettings* settings = freerdp_settings_new(0);
	rdpCertificateStore* store = nullptr;
	rdpCertificateStore* legacy = nullptr;
	char* base = GetCombinedPath(configPath, "https");
	rdpCertificateData* ipData = test_certificate_data_new(ipv6, 443, cert);
	rdpCertificateData* dnsData = test_certificate_data_new(dns, 443, cert);
	rdpCertificateData* upperData =
	    test_certificate_data_new("2001.DB8.1.2.3.4.ABCD.CAFE", 443, cert);
	rdpCertificateData* otherPort = test_certificate_data_new(dns, 444, cert);
	rdpCertificateData* changedData = test_certificate_data_new(dns, 443, replacement);
	if (!settings || !base || !ipData || !dnsData || !upperData || !otherPort || !changedData ||
	    !freerdp_settings_set_string(settings, FreeRDP_ConfigPath, base))
		goto out;
	legacy = freerdp_certificate_store_new(settings);
	if (!legacy || !freerdp_certificate_store_save_data(legacy, ipData) ||
	    !freerdp_settings_set_string(settings, FreeRDP_ConfigPath, configPath))
		goto out;
	store = freerdp_certificate_store_new_ex(settings, "https");
	/* Old filenames cannot prove which endpoint was accepted; do not import them. */
	if (!store ||
	    (freerdp_certificate_store_contains_data(store, ipData) != CERT_STORE_NOT_FOUND) ||
	    (freerdp_certificate_store_contains_data(store, dnsData) != CERT_STORE_NOT_FOUND) ||
	    !freerdp_certificate_store_save_data(store, ipData) ||
	    (freerdp_certificate_store_contains_data(store, ipData) != CERT_STORE_MATCH) ||
	    (freerdp_certificate_store_contains_data(store, dnsData) != CERT_STORE_NOT_FOUND) ||
	    !freerdp_certificate_store_save_data(store, dnsData))
		goto out;
	freerdp_certificate_store_free(store);
	store = freerdp_certificate_store_new_ex(settings, "https");
	if (!store || (freerdp_certificate_store_contains_data(store, ipData) != CERT_STORE_MATCH) ||
	    (freerdp_certificate_store_contains_data(store, upperData) != CERT_STORE_MATCH) ||
	    (freerdp_certificate_store_contains_data(store, otherPort) != CERT_STORE_NOT_FOUND) ||
	    !freerdp_certificate_store_save_data(store, changedData) ||
	    (freerdp_certificate_store_contains_data(store, ipData) != CERT_STORE_MATCH) ||
	    (freerdp_certificate_store_contains_data(store, dnsData) != CERT_STORE_MISMATCH) ||
	    (freerdp_certificate_store_contains_data(store, changedData) != CERT_STORE_MATCH) ||
	    !freerdp_certificate_store_remove_data(store, ipData) ||
	    (freerdp_certificate_store_contains_data(store, ipData) != CERT_STORE_NOT_FOUND) ||
	    (freerdp_certificate_store_contains_data(store, changedData) != CERT_STORE_MATCH))
		goto out;
	ret = TRUE;
out:
	if (!ret)
		(void)fprintf(stderr, "persisted HTTPS trust must not cross endpoint identities\n");
	if (legacy && ipData && !freerdp_certificate_store_remove_data(legacy, ipData))
		ret = FALSE;
	if (legacy)
		(void)RemoveDirectoryA(freerdp_certificate_store_get_hosts_path(legacy));
	if (!test_remove_pin(configPath, ipv6, 443) || !test_remove_pin(configPath, dns, 443))
		ret = FALSE;
	freerdp_certificate_data_free(ipData);
	freerdp_certificate_data_free(dnsData);
	freerdp_certificate_data_free(upperData);
	freerdp_certificate_data_free(otherPort);
	freerdp_certificate_data_free(changedData);
	freerdp_certificate_store_free(store);
	freerdp_certificate_store_free(legacy);
	freerdp_settings_free(settings);
	free(base);
	return ret;
}

static BOOL test_set_ca_file(const char* path)
{
#ifdef _WIN32
	/* OpenSSL reads the CRT environment, which SetEnvironmentVariable does not update. */
	return _putenv_s("SSL_CERT_FILE", path ? path : "") == 0;
#else
	return SetEnvironmentVariableA("SSL_CERT_FILE", path);
#endif
}

static EVP_PKEY* test_key_new(void)
{
	EVP_PKEY* key = nullptr;
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
	if (!ctx)
		return nullptr;
	if ((EVP_PKEY_keygen_init(ctx) <= 0) || (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) ||
	    (EVP_PKEY_keygen(ctx, &key) <= 0))
	{
		EVP_PKEY_free(key);
		key = nullptr;
	}
	EVP_PKEY_CTX_free(ctx);
	return key;
}

static BOOL test_extension(X509* cert, X509* issuer, int nid, const char* value)
{
	X509V3_CTX ctx = WINPR_C_ARRAY_INIT;
	X509V3_set_ctx(&ctx, issuer, cert, nullptr, nullptr, 0);
	X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &ctx, nid, value);
	if (!ext)
		return FALSE;
	const int rc = X509_add_ext(cert, ext, -1);
	X509_EXTENSION_free(ext);
	return rc == 1;
}

static X509* test_certificate_new(EVP_PKEY* key, X509* ca, EVP_PKEY* caKey, BOOL mismatch)
{
	X509* cert = X509_new();
	if (!cert)
		return nullptr;
	const char* name = ca ? "localhost" : "FreeRDP HTTP test CA";
	X509_NAME* subject = X509_get_subject_name(cert);
	if ((X509_set_version(cert, 2) != 1) ||
	    (ASN1_INTEGER_set(X509_get_serialNumber(cert), ca ? (mismatch ? 3 : 2) : 1) != 1) ||
	    !X509_gmtime_adj(X509_get_notBefore(cert), -3600) ||
	    !X509_gmtime_adj(X509_get_notAfter(cert), 86400) || (X509_set_pubkey(cert, key) != 1) ||
	    (X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC, (const BYTE*)name, -1, -1, 0) !=
	     1) ||
	    (X509_set_issuer_name(cert, ca ? X509_get_subject_name(ca) : subject) != 1) ||
	    !test_extension(cert, ca ? ca : cert, NID_basic_constraints,
	                    ca ? "critical,CA:FALSE" : "critical,CA:TRUE") ||
	    !test_extension(cert, ca ? ca : cert, NID_key_usage,
	                    ca ? "critical,digitalSignature,keyEncipherment"
	                       : "critical,keyCertSign,cRLSign"))
		goto fail;
	if (ca && (!test_extension(cert, ca, NID_ext_key_usage, "serverAuth") ||
	           !test_extension(cert, ca, NID_subject_alt_name,
	                           mismatch ? "DNS:wrong.example" : "DNS:localhost,IP:127.0.0.1")))
		goto fail;
	if (X509_sign(cert, caKey ? caKey : key, EVP_sha256()) <= 0)
		goto fail;
	return cert;
fail:
	X509_free(cert);
	return nullptr;
}

static DWORD WINAPI test_server_thread(void* arg)
{
	HttpTestServer* server = arg;
	BIO* connection = nullptr;
	char request[4096] = WINPR_C_ARRAY_INIT;
	size_t length = 0;
	fd_set fds;
	struct timeval timeout = { 10, 0 };
	FD_ZERO(&fds);
	FD_SET((SOCKET)server->socket, &fds);
	if (_select(server->socket + 1, &fds, nullptr, nullptr, &timeout) <= 0)
		return 1;
	if (BIO_do_accept(server->listener) != 1)
		return 1;
	connection = BIO_pop(server->listener);
	if (!connection)
		return 1;
	int fd = -1;
	if (BIO_get_fd(connection, &fd) < 0)
		goto out;
#ifdef _WIN32
	const DWORD receiveTimeout = 10000;
#else
	const struct timeval receiveTimeout = { 10, 0 };
#endif
	if (_setsockopt((SOCKET)fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&receiveTimeout,
	                sizeof(receiveTimeout)) != 0)
		goto out;
	if (BIO_do_handshake(connection) != 1)
		goto out;
	while (length < sizeof(request) - 1)
	{
		const int rc = BIO_read(connection, &request[length], (int)(sizeof(request) - length - 1));
		if (rc <= 0)
			break;
		server->received = TRUE;
		length += (size_t)rc;
		request[length] = '\0';
		const char* body = strstr(request, "\r\n\r\n");
		if (!body || (strlen(body + 4) < strlen(server->body)))
			continue;
		if (strcmp(body + 4, server->body) != 0)
			break;
		const char response[] = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}";
		server->replied =
		    BIO_write(connection, response, sizeof(response) - 1) == sizeof(response) - 1;
		break;
	}
out:
	BIO_free_all(connection);
	ERR_clear_error();
	return 0;
}

static BOOL test_listener_new(HttpTestServer* server, SSL_CTX* ssl, UINT16* port)
{
	struct sockaddr_in address = WINPR_C_ARRAY_INIT;
	socklen_t addressLength = sizeof(address);
	server->listener = BIO_new_accept("127.0.0.1:0");
	BIO* acceptBio = BIO_new_ssl(ssl, 0);
	if (!server->listener || !acceptBio)
	{
		BIO_free_all(acceptBio);
		return FALSE;
	}
	if (BIO_set_accept_bios(server->listener, acceptBio) != 1)
	{
		BIO_free_all(acceptBio);
		return FALSE;
	}
	if ((BIO_do_accept(server->listener) != 1) ||
	    (BIO_get_fd(server->listener, &server->socket) < 0) ||
	    (_getsockname((SOCKET)server->socket, (struct sockaddr*)&address, &addressLength) != 0))
		return FALSE;
	*port = _ntohs(address.sin_port);
	return TRUE;
}

static int test_verify_certificate(freerdp* instance, const BYTE* data, size_t length,
                                   const char* hostname, UINT16 port, DWORD flags)
{
	HttpTestContext* ctx = (HttpTestContext*)instance->context;
	BOOL foundCa = FALSE;
	size_t certificates = 0;
	size_t leaves = 0;
	ctx->calls++;
	if (!data || !length || (length > INT_MAX) || (strcmp(hostname, ctx->hostname) != 0) ||
	    (port != ctx->port) || (flags != ctx->flags))
		goto fail;
	BIO* pem = BIO_new_mem_buf(data, (int)length);
	if (!pem)
		goto fail;
	X509* cert = nullptr;
	while ((cert = PEM_read_bio_X509(pem, nullptr, nullptr, nullptr)))
	{
		certificates++;
		if (X509_cmp(cert, ctx->certificate) == 0)
			leaves++;
		if (certificates == 1)
		{
			if (X509_cmp(cert, ctx->certificate) != 0)
			{
				X509_free(cert);
				BIO_free(pem);
				goto fail;
			}
		}
		if (X509_cmp(cert, ctx->ca) == 0)
			foundCa = TRUE;
		X509_free(cert);
	}
	BIO_free(pem);
	ERR_clear_error();
	if (!foundCa || (certificates != 2) || (leaves != 1))
		goto fail;
	return ctx->decision;
fail:
	ctx->invalid = TRUE;
	return 0;
}

static BOOL test_request(const HttpTestCase* test, EVP_PKEY* key, X509* cert, X509* ca,
                         const char* caFile, const char* configPath)
{
	BOOL ret = FALSE;
	HttpTestServer server = WINPR_C_ARRAY_INIT;
	HttpTestContext ctx = WINPR_C_ARRAY_INIT;
	freerdp instance = WINPR_C_ARRAY_INIT;
	SSL_CTX* ssl = SSL_CTX_new(TLS_server_method());
	HANDLE thread = nullptr;
	BYTE* response = nullptr;
	WINPR_JSON* discovery = nullptr;
	size_t responseLength = 0;
	long status = 0;
	char base[128] = WINPR_C_ARRAY_INIT;
	char url[160] = WINPR_C_ARRAY_INIT;
	const char* body = test->discovery ? nullptr : "test=secret";
	ctx.context.instance = &instance;
	ctx.context.settings = freerdp_settings_new(0);
	ctx.ca = ca;
	ctx.certificate = cert;
	ctx.hostname = test->hostname;
	ctx.flags = test->mismatch ? VERIFY_CERT_FLAG_MISMATCH : VERIFY_CERT_FLAG_NONE;
	ctx.decision = test->decision;
	instance.context = &ctx.context;
	instance.VerifyX509Certificate = test->callback ? test_verify_certificate : nullptr;
	server.body = body ? body : "";
	if (!ctx.context.settings || !ssl ||
	    !freerdp_settings_set_string(ctx.context.settings, FreeRDP_ConfigPath,
	                                 test->storeFailure ? caFile : configPath) ||
	    !freerdp_settings_set_bool(ctx.context.settings, FreeRDP_AutoDenyCertificate,
	                               test->strict) ||
	    !freerdp_settings_set_bool(ctx.context.settings, FreeRDP_ExternalCertificateManagement,
	                               test->external) ||
	    !test_set_ca_file(test->trusted ? caFile : "") ||
	    (SSL_CTX_use_certificate(ssl, cert) != 1) || (SSL_CTX_use_PrivateKey(ssl, key) != 1) ||
	    (SSL_CTX_add1_chain_cert(ssl, ca) != 1))
		goto out;
	if (!test_listener_new(&server, ssl, &ctx.port))
		goto out;
	(void)snprintf(base, sizeof(base), "%s:%" PRIu16, test->hostname, ctx.port);
	(void)snprintf(url, sizeof(url), "https://%s/test", base);
	thread = CreateThread(nullptr, 0, test_server_thread, &server, 0, nullptr);
	if (!thread)
		goto out;
	BOOL rc = FALSE;
	if (test->discovery)
	{
		wLog* log = WLog_Get("TestHttp");
		discovery = test->legacy
		                ? freerdp_utils_aad_get_wellknown(log, base, "common")
		                : freerdp_utils_aad_get_wellknown_ex(&ctx.context, log, base, "common");
		rc = discovery != nullptr;
	}
	else
	{
		rc = test->legacy ? freerdp_http_request(url, body, &status, &response, &responseLength)
		                  : freerdp_http_request_ex(&ctx.context, url, body, &status, &response,
		                                            &responseLength);
	}
	if (WaitForSingleObject(thread, INFINITE) != WAIT_OBJECT_0)
		goto out;
	if ((rc != test->success) || (server.received != test->success) ||
	    (server.replied != test->success) || (ctx.calls != test->calls) || ctx.invalid)
		goto out;
	if (rc && !test->discovery &&
	    ((status != HTTP_STATUS_OK) || (responseLength != 2) || !response ||
	     (memcmp(response, "{}", 2) != 0)))
		goto out;
	if (!rc && (response || responseLength || status))
		goto out;
	ret = TRUE;
out:
	if (!ret)
		(void)fprintf(stderr, "%s failed (callback calls=%" PRIuz ", received=%d, replied=%d)\n",
		              test->name, ctx.calls, server.received, server.replied);
	if (thread)
	{
		(void)WaitForSingleObject(thread, INFINITE);
		CloseHandle(thread);
	}
	WINPR_JSON_Delete(discovery);
	free(response);
	BIO_free_all(server.listener);
	SSL_CTX_free(ssl);
	if (ctx.port && !test_remove_pin(configPath, test->hostname, ctx.port))
		ret = FALSE;
	freerdp_settings_free(ctx.context.settings);
	return ret;
}

static freerdp* test_context_new(X509* cert, X509* ca, UINT16 port, const char* configPath)
{
	freerdp* instance = freerdp_new();
	if (!instance)
		return nullptr;
	instance->ContextSize = sizeof(HttpTestContext);
	if (!freerdp_context_new(instance))
		goto fail;
	HttpTestContext* ctx = (HttpTestContext*)instance->context;
	ctx->certificate = cert;
	ctx->ca = ca;
	ctx->hostname = "127.0.0.1";
	ctx->port = port;
	instance->VerifyX509Certificate = test_verify_certificate;
	if (!freerdp_settings_set_string(ctx->context.settings, FreeRDP_ConfigPath, configPath) ||
	    !freerdp_settings_set_string(ctx->context.settings, FreeRDP_AcceptedCert, "target-cert") ||
	    !freerdp_settings_set_string(ctx->context.settings, FreeRDP_GatewayAcceptedCert,
	                                 "gateway-cert"))
		goto fail;
	return instance;
fail:
	freerdp_context_free(instance);
	freerdp_free(instance);
	return nullptr;
}

static BOOL test_exchange(HttpTestServer* server, HttpTestContext* ctx, BOOL success, size_t calls,
                          const char* name)
{
	BOOL ret = FALSE;
	long status = 0;
	size_t length = 0;
	BYTE* response = nullptr;
	char url[128] = WINPR_C_ARRAY_INIT;
	(void)snprintf(url, sizeof(url), "https://%s:%" PRIu16 "/test", ctx->hostname, ctx->port);
	server->body = "test=secret";
	server->received = FALSE;
	server->replied = FALSE;
	HANDLE thread = CreateThread(nullptr, 0, test_server_thread, server, 0, nullptr);
	if (!thread)
		return FALSE;
	const BOOL rc =
	    freerdp_http_request_ex(&ctx->context, url, server->body, &status, &response, &length);
	if (WaitForSingleObject(thread, INFINITE) != WAIT_OBJECT_0)
		goto out;
	if ((rc != success) || (server->received != success) || (server->replied != success) ||
	    (ctx->calls != calls) || ctx->invalid)
		goto out;
	if (success && ((status != HTTP_STATUS_OK) || (length != 2) || !response ||
	                (memcmp(response, "{}", 2) != 0)))
		goto out;
	if (!success && (response || length || status))
		goto out;
	if ((strcmp(freerdp_settings_get_string(ctx->context.settings, FreeRDP_AcceptedCert),
	            "target-cert") != 0) ||
	    (strcmp(freerdp_settings_get_string(ctx->context.settings, FreeRDP_GatewayAcceptedCert),
	            "gateway-cert") != 0))
		goto out;
	ret = TRUE;
out:
	if (!ret)
		(void)fprintf(stderr, "%s failed (decision=%d, calls=%" PRIuz ", received=%d)\n", name,
		              ctx->decision, ctx->calls, server->received);
	(void)WaitForSingleObject(thread, INFINITE);
	CloseHandle(thread);
	free(response);
	return ret;
}

static BOOL test_acceptance_lifetime(EVP_PKEY* key, X509* cert, X509* replacement, X509* ca,
                                     const char* configPath, int decision)
{
	BOOL ret = FALSE;
	UINT16 port = 0;
	UINT16 otherPort = 0;
	HttpTestServer server = WINPR_C_ARRAY_INIT;
	HttpTestServer other = WINPR_C_ARRAY_INIT;
	freerdp* instance = nullptr;
	rdpCertificateStore* targetStore = nullptr;
	char* targetPath = nullptr;
	SSL_CTX* ssl = SSL_CTX_new(TLS_server_method());
	SSL_CTX* changed = SSL_CTX_new(TLS_server_method());
	if (!ssl || !changed || !test_set_ca_file("") || (SSL_CTX_use_certificate(ssl, cert) != 1) ||
	    (SSL_CTX_use_PrivateKey(ssl, key) != 1) || (SSL_CTX_add1_chain_cert(ssl, ca) != 1) ||
	    (SSL_CTX_use_certificate(changed, replacement) != 1) ||
	    (SSL_CTX_use_PrivateKey(changed, key) != 1) ||
	    (SSL_CTX_add1_chain_cert(changed, ca) != 1) || !test_listener_new(&server, ssl, &port) ||
	    !test_listener_new(&other, ssl, &otherPort))
		goto out;
	instance = test_context_new(cert, ca, port, configPath);
	if (!instance)
		goto out;
	HttpTestContext* ctx = (HttpTestContext*)instance->context;
	ctx->decision = decision;
	if (!test_exchange(&server, ctx, TRUE, 1, "initial acceptance"))
		goto out;
	ctx->decision = 0;
	if (!test_exchange(&server, ctx, TRUE, 1, "repeat request without prompting"))
		goto out;
	ctx->port = otherPort;
	if (!test_exchange(&other, ctx, FALSE, 2, "acceptance must not cross ports"))
		goto out;
	ctx->port = port;
	ctx->hostname = "localhost";
	if (!test_exchange(&server, ctx, FALSE, 3, "acceptance must not cross hosts"))
		goto out;
	ctx->hostname = "127.0.0.1";

	BIO* acceptBio = BIO_new_ssl(changed, 0);
	if (!acceptBio)
		goto out;
	if (BIO_set_accept_bios(server.listener, acceptBio) != 1)
	{
		BIO_free_all(acceptBio);
		goto out;
	}
	ctx->certificate = replacement;
	ctx->flags = VERIFY_CERT_FLAG_CHANGED | VERIFY_CERT_FLAG_MISMATCH;
	if (!test_exchange(&server, ctx, FALSE, 4, "changed certificate must be reviewed"))
		goto out;

	targetStore = freerdp_certificate_store_new(ctx->context.settings);
	if (!targetStore)
		goto out;
	targetPath = freerdp_certificate_store_get_cert_path(targetStore, ctx->hostname, port);
	if (!targetPath || winpr_PathFileExists(targetPath))
		goto out;
	freerdp_context_free(instance);
	freerdp_free(instance);
	instance = test_context_new(cert, ca, port, configPath);
	if (!instance)
		goto out;
	ctx = (HttpTestContext*)instance->context;
	acceptBio = BIO_new_ssl(ssl, 0);
	if (!acceptBio)
		goto out;
	if (BIO_set_accept_bios(server.listener, acceptBio) != 1)
	{
		BIO_free_all(acceptBio);
		goto out;
	}
	if (decision == 1)
	{
		/* Stored trust survives a fresh context and works without a prompt in strict mode. */
		instance->VerifyX509Certificate = nullptr;
		if (!freerdp_settings_set_bool(ctx->context.settings, FreeRDP_AutoDenyCertificate, TRUE) ||
		    !test_exchange(&server, ctx, TRUE, 0, "persisted acceptance in a new context"))
			goto out;
	}
	else if (!test_exchange(&server, ctx, FALSE, 1, "session acceptance must expire"))
		goto out;
	ret = TRUE;
out:
	if (!ret)
		(void)fprintf(stderr, "certificate acceptance lifetime failed for decision %d\n", decision);
	if (port && !test_remove_pin(configPath, "127.0.0.1", port))
		ret = FALSE;
	if (otherPort && !test_remove_pin(configPath, "127.0.0.1", otherPort))
		ret = FALSE;
	free(targetPath);
	freerdp_certificate_store_free(targetStore);
	freerdp_context_free(instance);
	freerdp_free(instance);
	BIO_free_all(server.listener);
	BIO_free_all(other.listener);
	SSL_CTX_free(ssl);
	SSL_CTX_free(changed);
	return ret;
}

int TestHttp(WINPR_ATTR_UNUSED int argc, WINPR_ATTR_UNUSED char* argv[])
{
	int rc = -1;
#ifndef _WIN32
	void (*savedSigpipe)(int) = signal(SIGPIPE, SIG_IGN);
#endif
	WSADATA wsa = WINPR_C_ARRAY_INIT;
	char directory[MAX_PATH] = WINPR_C_ARRAY_INIT;
	char caFile[MAX_PATH] = WINPR_C_ARRAY_INIT;
	char configPath[MAX_PATH] = WINPR_C_ARRAY_INIT;
	char* savedCa = getenv("SSL_CERT_FILE") ? _strdup(getenv("SSL_CERT_FILE")) : nullptr;
	FILE* file = nullptr;
	EVP_PKEY* caKey = test_key_new();
	EVP_PKEY* key = test_key_new();
	X509* ca = caKey ? test_certificate_new(caKey, nullptr, nullptr, FALSE) : nullptr;
	X509* cert = (key && ca) ? test_certificate_new(key, ca, caKey, FALSE) : nullptr;
	X509* mismatch = (key && ca) ? test_certificate_new(key, ca, caKey, TRUE) : nullptr;
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
		goto out;
	if (!key || !ca || !cert || !mismatch || !GetTempPathA(sizeof(directory), directory) ||
	    !GetTempFileNameA(directory, "http", 0, caFile))
		goto out;
	file = fopen(caFile, "wb");
	if (!file || (PEM_write_X509(file, ca) != 1))
		goto out;
	fclose(file);
	file = nullptr;
	if (!GetTempFileNameA(directory, "fht", 0, configPath) || !DeleteFileA(configPath) ||
	    !CreateDirectoryA(configPath, nullptr))
		goto out;
	if (!test_persisted_endpoint_identity(cert, mismatch, configPath))
		goto out;
	const HttpTestCase tests[] = {
		{ "external accept", "localhost", FALSE, FALSE, TRUE, TRUE, 1, FALSE, FALSE, TRUE, 1 },
		{ "external session accept", "localhost", FALSE, FALSE, TRUE, TRUE, 2, FALSE, FALSE, TRUE,
		  1 },
		{ "external reject", "localhost", FALSE, FALSE, TRUE, TRUE, 0, FALSE, FALSE, FALSE, 1 },
		{ "external error", "localhost", FALSE, FALSE, TRUE, TRUE, -1, FALSE, FALSE, FALSE, 1 },
		{ "external trusted reject", "localhost", FALSE, TRUE, TRUE, TRUE, 0, FALSE, FALSE, FALSE,
		  1 },
		{ "external mismatch", "localhost", TRUE, TRUE, TRUE, TRUE, 0, FALSE, FALSE, FALSE, 1 },
		{ "fallback accept", "localhost", FALSE, FALSE, FALSE, TRUE, 1, FALSE, FALSE, TRUE, 1 },
		{ "fallback reject", "localhost", FALSE, FALSE, FALSE, TRUE, 0, FALSE, FALSE, FALSE, 1 },
		{ "trusted bypasses fallback", "localhost", FALSE, TRUE, FALSE, TRUE, 0, FALSE, FALSE, TRUE,
		  0 },
		{ "fallback mismatch", "localhost", TRUE, TRUE, FALSE, TRUE, 0, FALSE, FALSE, FALSE, 1 },
		{ "legacy trusted", "localhost", FALSE, TRUE, FALSE, FALSE, 0, TRUE, FALSE, TRUE, 0 },
		{ "legacy untrusted", "localhost", FALSE, FALSE, FALSE, FALSE, 0, TRUE, FALSE, FALSE, 0 },
		{ "legacy mismatch", "localhost", TRUE, TRUE, FALSE, FALSE, 0, TRUE, FALSE, FALSE, 0 },
		{ "IP subject alternative name", "127.0.0.1", FALSE, TRUE, FALSE, FALSE, 0, TRUE, FALSE,
		  TRUE, 0 },
		{ "IP mismatch", "127.0.0.1", TRUE, TRUE, FALSE, TRUE, 0, FALSE, FALSE, FALSE, 1 },
		{ "external discovery", "localhost", FALSE, FALSE, TRUE, TRUE, 1, FALSE, TRUE, TRUE, 1 },
		{ "legacy discovery", "localhost", FALSE, TRUE, FALSE, FALSE, 0, TRUE, TRUE, TRUE, 0 },
		{ "strict unknown", "localhost", FALSE, FALSE, FALSE, TRUE, 1, FALSE, FALSE, FALSE, 0,
		  TRUE },
		{ "strict without callback", "localhost", FALSE, FALSE, FALSE, FALSE, 0, FALSE, FALSE,
		  FALSE, 0, TRUE },
		{ "strict mismatch", "localhost", TRUE, TRUE, FALSE, TRUE, 1, FALSE, FALSE, FALSE, 0,
		  TRUE },
		{ "strict trusted", "localhost", FALSE, TRUE, FALSE, TRUE, 1, FALSE, FALSE, TRUE, 0, TRUE },
		{ "external strict delegates", "localhost", FALSE, FALSE, TRUE, TRUE, 1, FALSE, FALSE, TRUE,
		  1, TRUE },
		{ "external strict rejects", "localhost", FALSE, FALSE, TRUE, TRUE, 0, FALSE, FALSE, FALSE,
		  1, TRUE },
		{ "store failure rejects request", "127.0.0.1", FALSE, FALSE, FALSE, TRUE, 1, FALSE, FALSE,
		  FALSE, 1, FALSE, TRUE },
		{ "session acceptance needs context", "127.0.0.1", FALSE, FALSE, FALSE, TRUE, 2, FALSE,
		  FALSE, FALSE, 1 },
	};
	for (size_t x = 0; x < ARRAYSIZE(tests); x++)
	{
		if (!test_request(&tests[x], key, tests[x].mismatch ? mismatch : cert, ca, caFile,
		                  configPath))
			goto out;
	}
	if (!test_acceptance_lifetime(key, cert, mismatch, ca, configPath, 1) ||
	    !test_acceptance_lifetime(key, cert, mismatch, ca, configPath, 2))
		goto out;
	/* External management must fail closed when no callback is registered. */
	{
		freerdp instance = WINPR_C_ARRAY_INIT;
		rdpContext context = WINPR_C_ARRAY_INIT;
		BYTE* response = nullptr;
		size_t length = 123;
		long status = 123;
		context.instance = &instance;
		context.settings = freerdp_settings_new(0);
		instance.context = &context;
		BOOL valid = context.settings &&
		             freerdp_settings_set_bool(context.settings,
		                                       FreeRDP_ExternalCertificateManagement, TRUE) &&
		             !freerdp_http_request_ex(&context, "https://127.0.0.1:1/", "test=secret",
		                                      &status, &response, &length) &&
		             !response && !length && !status;
		free(response);
		freerdp_settings_free(context.settings);
		if (!valid)
			goto out;
	}
	rc = 0;
out:
	if (file)
		fclose(file);
	if (caFile[0])
		DeleteFileA(caFile);
	if (configPath[0])
		(void)RemoveDirectoryA(configPath);
	if (!test_set_ca_file(savedCa))
		rc = -1;
	free(savedCa);
	X509_free(mismatch);
	X509_free(cert);
	X509_free(ca);
	EVP_PKEY_free(key);
	EVP_PKEY_free(caKey);
	WSACleanup();
#ifndef _WIN32
	(void)signal(SIGPIPE, savedSigpipe);
#endif
	return rc;
}
