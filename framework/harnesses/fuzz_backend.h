#pragma once

#include "apr.h"
#include "apr_pools.h"

extern int g_backend_enabled;
extern const char *g_backend_buf;
extern apr_size_t g_backend_size;

void backend_register_hooks(apr_pool_t *p);
