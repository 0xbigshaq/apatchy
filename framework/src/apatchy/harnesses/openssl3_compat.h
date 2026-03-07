/*
 * Shim for APIs removed (not just deprecated) in OpenSSL 3.0.
 * Force-included via -include during builds of httpd <= 2.4.51.
 */
#ifndef OPENSSL3_COMPAT_H
#define OPENSSL3_COMPAT_H

#ifndef ERR_GET_FUNC
#define ERR_GET_FUNC(l) 0
#endif

#endif
