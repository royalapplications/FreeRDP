/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Certificate store internals
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

#ifndef FREERDP_LIB_CRYPTO_CERTIFICATE_STORE_H
#define FREERDP_LIB_CRYPTO_CERTIFICATE_STORE_H

#include <freerdp/crypto/certificate_store.h>

/* Namespaced stores hash hostnames; a null subpath keeps the legacy RDP filenames. */
WINPR_ATTR_MALLOC(freerdp_certificate_store_free, 1)
WINPR_ATTR_NODISCARD
FREERDP_LOCAL rdpCertificateStore* freerdp_certificate_store_new_ex(const rdpSettings* settings,
                                                                    const char* subpath);

#endif /* FREERDP_LIB_CRYPTO_CERTIFICATE_STORE_H */
