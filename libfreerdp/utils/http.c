/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Simple HTTP client request utility
 *
 * Copyright 2023 Isaac Klein <fifthdegree@protonmail.com>
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
#include <freerdp/utils/http.h>
#include <freerdp/freerdp.h>

#include <winpr/assert.h>
#include <winpr/string.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "../core/utils.h"
#include "../core/rdp.h"
#include "../crypto/certificate.h"
#include "../crypto/certificate_store.h"

#include <freerdp/log.h>
#define TAG FREERDP_TAG("utils.http")

static const char get_header_fmt[] = "GET %s HTTP/1.1\r\n"
                                     "Host: %s\r\n"
                                     "\r\n";

static const char post_header_fmt[] = "POST %s HTTP/1.1\r\n"
                                      "Host: %s\r\n"
                                      "Content-Type: application/x-www-form-urlencoded\r\n"
                                      "Content-Length: %lu\r\n"
                                      "\r\n";

#define log_errors(log, msg) log_errors_(log, msg, __FILE__, __func__, __LINE__)
static void log_errors_(wLog* log, const char* msg, const char* file, const char* fkt, size_t line)
{
	const DWORD level = WLOG_ERROR;
	unsigned long ec = 0;

	if (!WLog_IsLevelActive(log, level))
		return;

	BOOL error_logged = FALSE;
	while ((ec = ERR_get_error()))
	{
		error_logged = TRUE;
		WLog_PrintTextMessage(log, level, line, file, fkt, "%s: %s", msg,
		                      ERR_error_string(ec, nullptr));
	}
	if (!error_logged)
		WLog_PrintTextMessage(log, level, line, file, fkt, "%s (no details available)", msg);
}

static int get_line(BIO* bio, char* buffer, size_t size)
{
#if !defined(OPENSSL_VERSION_MAJOR) || (OPENSSL_VERSION_MAJOR < 3)
	if (size <= 1)
		return -1;

	size_t pos = 0;
	do
	{
		int rc = BIO_read(bio, &buffer[pos], 1);
		if (rc <= 0)
			return rc;
		char cur = buffer[pos];
		pos += rc;
		if ((cur == '\n') || (pos >= size - 1))
		{
			buffer[pos] = '\0';
			return (int)pos;
		}
	} while (1);
#else
	if (size > INT32_MAX)
		return -1;
	return BIO_get_line(bio, buffer, (int)size);
#endif
}

/* Defer certificate errors to http_verify_certificate, before sending HTTP data. */
static int http_verify_callback(WINPR_ATTR_UNUSED int preverify_ok,
                                WINPR_ATTR_UNUSED X509_STORE_CTX* store)
{
	return 1;
}

static BOOL http_same_endpoint(const rdpCertificateData* a, const rdpCertificateData* b)
{
	return (freerdp_certificate_data_get_port(a) == freerdp_certificate_data_get_port(b)) &&
	       (_stricmp(freerdp_certificate_data_get_host(a), freerdp_certificate_data_get_host(b)) ==
	        0);
}

static freerdp_certificate_store_result http_cached_certificate(rdpContext* context,
                                                                const rdpCertificateData* data)
{
	freerdp_certificate_store_result result = CERT_STORE_NOT_FOUND;
	rdpRdp* rdp = context->rdp;
	if (!rdp)
		return result;
	EnterCriticalSection(&rdp->critical);
	if (rdp->httpAcceptedCertificates)
	{
		for (size_t x = 0; x < ArrayList_Count(rdp->httpAcceptedCertificates); x++)
		{
			const rdpCertificateData* cached = ArrayList_GetItem(rdp->httpAcceptedCertificates, x);
			if (http_same_endpoint(cached, data))
			{
				result = freerdp_certificate_data_equal(cached, data) ? CERT_STORE_MATCH
				                                                      : CERT_STORE_MISMATCH;
				break;
			}
		}
	}
	LeaveCriticalSection(&rdp->critical);
	return result;
}

static void http_certificate_free(void* data)
{
	freerdp_certificate_data_free(data);
}

/* Takes ownership of data on success. */
static BOOL http_cache_certificate(rdpContext* context, rdpCertificateData* data)
{
	BOOL ret = FALSE;
	rdpRdp* rdp = context->rdp;
	if (!rdp)
		return FALSE;
	EnterCriticalSection(&rdp->critical);
	if (!rdp->httpAcceptedCertificates)
	{
		rdp->httpAcceptedCertificates = ArrayList_New(FALSE);
		if (!rdp->httpAcceptedCertificates)
			goto out;
		ArrayList_Object(rdp->httpAcceptedCertificates)->fnObjectFree = http_certificate_free;
	}
	for (size_t x = 0; x < ArrayList_Count(rdp->httpAcceptedCertificates); x++)
	{
		rdpCertificateData* cached = ArrayList_GetItem(rdp->httpAcceptedCertificates, x);
		if (http_same_endpoint(cached, data))
		{
			ret = ArrayList_SetItem(rdp->httpAcceptedCertificates, x, data);
			if (ret)
				freerdp_certificate_data_free(cached);
			goto out;
		}
	}
	ret = ArrayList_Append(rdp->httpAcceptedCertificates, data);
out:
	LeaveCriticalSection(&rdp->critical);
	return ret;
}

static rdpCertificate* http_peer_certificate(SSL* ssl, const X509* peer)
{
	rdpCertificate* cert = nullptr;
	STACK_OF(X509)* chain = sk_X509_new_null();
	STACK_OF(X509)* sent = SSL_get_peer_cert_chain(ssl);
	if (!chain)
		return nullptr;
	/* OpenSSL's client-side chain already includes the leaf certificate. */
	for (int x = 0; sent && (x < sk_X509_num(sent)); x++)
	{
		X509* item = sk_X509_value(sent, x);
		if ((X509_cmp(peer, item) != 0) && !sk_X509_push(chain, item))
			goto out;
	}
	cert = freerdp_certificate_new_from_x509(peer, chain);
out:
	/* The entries are borrowed from SSL; the certificate constructor copies them. */
	sk_X509_free(chain);
	return cert;
}

static BOOL http_verify_certificate(wLog* log, rdpContext* context, SSL* ssl, const char* hostname,
                                    UINT16 port, BOOL external)
{
	BOOL ret = FALSE;
	size_t length = 0;
	char* pem = nullptr;
	rdpCertificate* cert = nullptr;
	rdpCertificateData* data = nullptr;
	rdpCertificateStore* store = nullptr;
	DWORD flags = VERIFY_CERT_FLAG_NONE;
	X509* peer = SSL_get_peer_certificate(ssl);
	if (!peer)
	{
		log_errors(log, "could not get peer certificate");
		return FALSE;
	}

	const long result = SSL_get_verify_result(ssl);
	if (!external && (result == X509_V_OK))
	{
		ret = TRUE;
		goto out;
	}

	if (!context)
	{
		WLog_Print(log, WLOG_ERROR, "certificate verification failed: %s",
		           X509_verify_cert_error_string(result));
		goto out;
	}

	cert = http_peer_certificate(ssl, peer);
	if (!cert)
		goto out;
	if (!external)
	{
		data = freerdp_certificate_data_new(hostname, port, cert);
		if (!data)
			goto out;
		const freerdp_certificate_store_result cached = http_cached_certificate(context, data);
		if (cached == CERT_STORE_MATCH)
		{
			ret = TRUE;
			goto out;
		}
		/* Keep HTTPS trust decisions separate from RDP and gateway certificates. */
		store = freerdp_certificate_store_new_ex(context->settings, "https");
		const freerdp_certificate_store_result stored =
		    store ? freerdp_certificate_store_contains_data(store, data) : CERT_STORE_NOT_FOUND;
		if (stored == CERT_STORE_MATCH)
		{
			ret = TRUE;
			goto out;
		}
		if (freerdp_settings_get_bool(context->settings, FreeRDP_AutoDenyCertificate))
		{
			WLog_Print(log, WLOG_ERROR, "HTTPS certificate denied for %s:%" PRIu16, hostname, port);
			goto out;
		}
		if ((cached == CERT_STORE_MISMATCH) || (stored == CERT_STORE_MISMATCH))
			flags |= VERIFY_CERT_FLAG_CHANGED;
	}
	if (!context->instance->VerifyX509Certificate)
	{
		WLog_Print(log, WLOG_ERROR, "No VerifyX509Certificate callback registered!");
		goto out;
	}

	const int match =
	    utils_is_valid_ip(hostname)
	        ? X509_check_ip_asc(peer, hostname, 0)
	        : X509_check_host(peer, hostname, 0, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS, nullptr);
	if (match < 0)
		goto out;
	if (match == 0)
		flags |= VERIFY_CERT_FLAG_MISMATCH;

	pem = freerdp_certificate_get_pem(cert, &length);
	if (!pem)
		goto out;

	const int decision = context->instance->VerifyX509Certificate(
	    context->instance, (const BYTE*)pem, length, hostname, port, flags);
	if (external)
		ret = decision > 0;
	else if (decision == 1)
	{
		ret = store && freerdp_certificate_store_save_data(store, data);
		if (ret && context->rdp)
		{
			ret = http_cache_certificate(context, data);
			if (ret)
				data = nullptr;
		}
	}
	else if (decision > 1)
	{
		ret = http_cache_certificate(context, data);
		if (ret)
			data = nullptr;
	}
	if (!ret)
		WLog_Print(log, WLOG_ERROR, "HTTPS certificate rejected for %s:%" PRIu16, hostname, port);

out:
	free(pem);
	freerdp_certificate_data_free(data);
	freerdp_certificate_store_free(store);
	freerdp_certificate_free(cert);
	X509_free(peer);
	return ret;
}

BOOL freerdp_http_request(const char* url, const char* body, long* status_code, BYTE** response,
                          size_t* response_length)
{
	return freerdp_http_request_ex(nullptr, url, body, status_code, response, response_length);
}

BOOL freerdp_http_request_ex(rdpContext* context, const char* url, const char* body,
                             long* status_code, BYTE** response, size_t* response_length)
{
	BOOL ret = FALSE;
	char* authority = nullptr;
	char* hostname = nullptr;
	char* service = nullptr;
	UINT16 port = 443;
	const char* path = nullptr;
	char* headers = nullptr;
	size_t size = 0;
	int status = 0;
	char buffer[1024] = WINPR_C_ARRAY_INIT;
	BIO* bio = nullptr;
	SSL_CTX* ssl_ctx = nullptr;
	SSL* ssl = nullptr;

	WINPR_ASSERT(status_code);
	WINPR_ASSERT(response);
	WINPR_ASSERT(response_length);
	WINPR_ASSERT(!context || context->instance);
	WINPR_ASSERT(!context || context->settings);

	const BOOL external = context && freerdp_settings_get_bool(
	                                     context->settings, FreeRDP_ExternalCertificateManagement);
	const BOOL callback = context && context->instance->VerifyX509Certificate;

	wLog* log = WLog_Get(TAG);
	WINPR_ASSERT(log);

	*response = nullptr;
	*response_length = 0;
	*status_code = 0;

	if (external && !callback)
	{
		WLog_Print(log, WLOG_ERROR, "No VerifyX509Certificate callback registered!");
		goto out;
	}

	if (!url || strnlen(url, 8) < 8 || strncmp(url, "https://", 8) != 0 ||
	    !(path = strchr(url + 8, '/')))
	{
		WLog_Print(log, WLOG_ERROR, "invalid url provided");
		goto out;
	}

	{
		const size_t len = WINPR_ASSERTING_INT_CAST(size_t, path - (url + 8));
		authority = strndup(&url[8], len);
	}
	if (!authority || !BIO_parse_hostserv(authority, &hostname, &service, BIO_PARSE_PRIO_HOST) ||
	    !hostname || !hostname[0] || strchr(hostname, '@'))
	{
		WLog_Print(log, WLOG_ERROR, "invalid HTTPS authority");
		goto out;
	}
	if (service)
	{
		char* end = nullptr;
		errno = 0;
		const unsigned long value = strtoul(service, &end, 10);
		if (errno || !service[0] || !end || *end || (value == 0) || (value > UINT16_MAX))
		{
			WLog_Print(log, WLOG_ERROR, "invalid HTTPS port");
			goto out;
		}
		port = (UINT16)value;
	}

	{
		size_t blen = 0;
		if (body)
		{
			blen = strlen(body);
			if (winpr_asprintf(&headers, &size, post_header_fmt, path, authority, blen) < 0)
				goto out;
		}
		else
		{
			if (winpr_asprintf(&headers, &size, get_header_fmt, path, authority) < 0)
				goto out;
		}

		ssl_ctx = SSL_CTX_new(TLS_client_method());

		if (!ssl_ctx)
		{
			log_errors(log, "could not set up ssl context");
			goto out;
		}

		if (!external && !SSL_CTX_set_default_verify_paths(ssl_ctx))
		{
			log_errors(log, "could not set ssl context verify paths");
			goto out;
		}

		SSL_CTX_set_verify(ssl_ctx, external ? SSL_VERIFY_NONE : SSL_VERIFY_PEER,
		                   context ? http_verify_callback : nullptr);

		SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);

		bio = BIO_new_ssl_connect(ssl_ctx);
		if (!bio)
		{
			log_errors(log, "could not set up connection");
			goto out;
		}

		if (BIO_set_conn_port(bio, service ? service : "https") <= 0)
		{
			log_errors(log, "could not set port");
			goto out;
		}

		/* The connect BIO parses host:port itself and requires brackets around IPv6 addresses. */
		if (!BIO_set_conn_hostname(bio, authority))
		{
			log_errors(log, "could not set hostname");
			goto out;
		}

		BIO_get_ssl(bio, &ssl);
		if (!ssl)
		{
			log_errors(log, "could not get ssl");
			goto out;
		}

		SSL_set_hostflags(ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
		const BOOL isIP = utils_is_valid_ip(hostname);
		const int verifyHost = isIP ? X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(ssl), hostname)
		                            : SSL_set1_host(ssl, hostname);
		if (verifyHost != 1)
		{
			log_errors(log, "could not set certificate hostname");
			goto out;
		}

		if (!isIP && !SSL_set_tlsext_host_name(ssl, hostname))
		{
			log_errors(log, "could not set sni hostname");
			goto out;
		}

		ERR_clear_error();
		if (BIO_do_handshake(bio) != 1)
		{
			log_errors(log, "TLS handshake failed");
			goto out;
		}
		if (!http_verify_certificate(log, context, ssl, hostname, port, external))
			goto out;

		WLog_Print(log, WLOG_DEBUG, "headers:\n%s", headers);
		ERR_clear_error();

		{
			const size_t hlen = strnlen(headers, size);
			if (hlen > INT32_MAX)
				goto out;

			if (BIO_write(bio, headers, (int)hlen) < 0)
			{
				log_errors(log, "could not write headers");
				goto out;
			}

			if (body)
			{
				WLog_Print(log, WLOG_DEBUG, "body:\n%s", body);

				if (blen > INT_MAX)
				{
					WLog_Print(log, WLOG_ERROR, "body too long!");
					goto out;
				}

				ERR_clear_error();
				if (BIO_write(bio, body, (int)blen) < 0)
				{
					log_errors(log, "could not write body");
					goto out;
				}
			}
		}
	}

	status = get_line(bio, buffer, sizeof(buffer));
	if (status <= 0)
	{
		log_errors(log, "could not read response");
		goto out;
	}

	const char header[9] = { 'H', 'T', 'T', 'P', '/', '1', '.', '1', ' ' };
	if ((status < (INT64)sizeof(header)) || (strncmp(header, buffer, sizeof(header)) != 0))
	{
		WLog_Print(log, WLOG_ERROR, "invalid HTTP status header");
		goto out;
	}

	errno = 0;
	*status_code = strtol(&buffer[sizeof(header)], nullptr, 0);
	if (errno != 0)
	{
		char ebuffer[256] = WINPR_C_ARRAY_INIT;
		WLog_Print(log, WLOG_ERROR, "invalid HTTP status line: %s [%d]",
		           winpr_strerror(errno, ebuffer, sizeof(ebuffer)), errno);
		goto out;
	}

	do
	{
		status = get_line(bio, buffer, sizeof(buffer));
		if (status <= 0)
		{
			log_errors(log, "could not read response");
			goto out;
		}

		char* val = nullptr;
		char* name = strtok_s(buffer, ":", &val);
		if (name && (_stricmp(name, "content-length") == 0))
		{
			errno = 0;
			*response_length = strtoul(val, nullptr, 10);
			if (errno)
			{
				char ebuffer[256] = WINPR_C_ARRAY_INIT;
				WLog_Print(log, WLOG_ERROR, "could not parse content length (%s): %s [%d]", val,
				           winpr_strerror(errno, ebuffer, sizeof(ebuffer)), errno);
				goto out;
			}
		}
	} while (strcmp(buffer, "\r\n") != 0);

	if (*response_length > 0)
	{
		if (*response_length > INT_MAX)
		{
			WLog_Print(log, WLOG_ERROR, "response too long!");
			goto out;
		}

		*response = calloc(1, *response_length + 1);
		if (!*response)
			goto out;

		BYTE* p = *response;
		size_t left = *response_length;
		while (left > 0)
		{
			const int rd = (left < INT32_MAX) ? (int)left : INT32_MAX;
			status = BIO_read(bio, p, rd);
			if (status <= 0)
			{
				log_errors(log, "could not read response");
				goto out;
			}
			p += status;
			if ((size_t)status > left)
				break;
			left -= (size_t)status;
		}
	}

	WLog_Print(log, WLOG_DEBUG, "response[%" PRIuz "]:\n%s", *response_length,
	           (const char*)(*response));
	ret = TRUE;

out:
	if (!ret)
	{
		free(*response);
		*response = nullptr;
		*response_length = 0;
	}
	free(authority);
	OPENSSL_free(hostname);
	OPENSSL_free(service);
	free(headers);
	BIO_free_all(bio);
	SSL_CTX_free(ssl_ctx);
	return ret;
}

const char* freerdp_http_status_string(long status)
{
	switch (status)
	{
		case HTTP_STATUS_CONTINUE:
			return "HTTP_STATUS_CONTINUE";
		case HTTP_STATUS_SWITCH_PROTOCOLS:
			return "HTTP_STATUS_SWITCH_PROTOCOLS";
		case HTTP_STATUS_OK:
			return "HTTP_STATUS_OK";
		case HTTP_STATUS_CREATED:
			return "HTTP_STATUS_CREATED";
		case HTTP_STATUS_ACCEPTED:
			return "HTTP_STATUS_ACCEPTED";
		case HTTP_STATUS_PARTIAL:
			return "HTTP_STATUS_PARTIAL";
		case HTTP_STATUS_NO_CONTENT:
			return "HTTP_STATUS_NO_CONTENT";
		case HTTP_STATUS_RESET_CONTENT:
			return "HTTP_STATUS_RESET_CONTENT";
		case HTTP_STATUS_PARTIAL_CONTENT:
			return "HTTP_STATUS_PARTIAL_CONTENT";
		case HTTP_STATUS_WEBDAV_MULTI_STATUS:
			return "HTTP_STATUS_WEBDAV_MULTI_STATUS";
		case HTTP_STATUS_AMBIGUOUS:
			return "HTTP_STATUS_AMBIGUOUS";
		case HTTP_STATUS_MOVED:
			return "HTTP_STATUS_MOVED";
		case HTTP_STATUS_REDIRECT:
			return "HTTP_STATUS_REDIRECT";
		case HTTP_STATUS_REDIRECT_METHOD:
			return "HTTP_STATUS_REDIRECT_METHOD";
		case HTTP_STATUS_NOT_MODIFIED:
			return "HTTP_STATUS_NOT_MODIFIED";
		case HTTP_STATUS_USE_PROXY:
			return "HTTP_STATUS_USE_PROXY";
		case HTTP_STATUS_REDIRECT_KEEP_VERB:
			return "HTTP_STATUS_REDIRECT_KEEP_VERB";
		case HTTP_STATUS_BAD_REQUEST:
			return "HTTP_STATUS_BAD_REQUEST";
		case HTTP_STATUS_DENIED:
			return "HTTP_STATUS_DENIED";
		case HTTP_STATUS_PAYMENT_REQ:
			return "HTTP_STATUS_PAYMENT_REQ";
		case HTTP_STATUS_FORBIDDEN:
			return "HTTP_STATUS_FORBIDDEN";
		case HTTP_STATUS_NOT_FOUND:
			return "HTTP_STATUS_NOT_FOUND";
		case HTTP_STATUS_BAD_METHOD:
			return "HTTP_STATUS_BAD_METHOD";
		case HTTP_STATUS_NONE_ACCEPTABLE:
			return "HTTP_STATUS_NONE_ACCEPTABLE";
		case HTTP_STATUS_PROXY_AUTH_REQ:
			return "HTTP_STATUS_PROXY_AUTH_REQ";
		case HTTP_STATUS_REQUEST_TIMEOUT:
			return "HTTP_STATUS_REQUEST_TIMEOUT";
		case HTTP_STATUS_CONFLICT:
			return "HTTP_STATUS_CONFLICT";
		case HTTP_STATUS_GONE:
			return "HTTP_STATUS_GONE";
		case HTTP_STATUS_LENGTH_REQUIRED:
			return "HTTP_STATUS_LENGTH_REQUIRED";
		case HTTP_STATUS_PRECOND_FAILED:
			return "HTTP_STATUS_PRECOND_FAILED";
		case HTTP_STATUS_REQUEST_TOO_LARGE:
			return "HTTP_STATUS_REQUEST_TOO_LARGE";
		case HTTP_STATUS_URI_TOO_LONG:
			return "HTTP_STATUS_URI_TOO_LONG";
		case HTTP_STATUS_UNSUPPORTED_MEDIA:
			return "HTTP_STATUS_UNSUPPORTED_MEDIA";
		case HTTP_STATUS_RETRY_WITH:
			return "HTTP_STATUS_RETRY_WITH";
		case HTTP_STATUS_SERVER_ERROR:
			return "HTTP_STATUS_SERVER_ERROR";
		case HTTP_STATUS_NOT_SUPPORTED:
			return "HTTP_STATUS_NOT_SUPPORTED";
		case HTTP_STATUS_BAD_GATEWAY:
			return "HTTP_STATUS_BAD_GATEWAY";
		case HTTP_STATUS_SERVICE_UNAVAIL:
			return "HTTP_STATUS_SERVICE_UNAVAIL";
		case HTTP_STATUS_GATEWAY_TIMEOUT:
			return "HTTP_STATUS_GATEWAY_TIMEOUT";
		case HTTP_STATUS_VERSION_NOT_SUP:
			return "HTTP_STATUS_VERSION_NOT_SUP";
		default:
			return "HTTP_STATUS_UNKNOWN";
	}
}

const char* freerdp_http_status_string_format(long status, char* buffer, size_t size)
{
	const char* code = freerdp_http_status_string(status);
	(void)_snprintf(buffer, size, "%s [%ld]", code, status);
	return buffer;
}
