/**
 @brief AMP Kernel Logger
        Copyright 2015-2018 Cisco Systems
        GNU Public License
 @author Craig Davison <crdaviso@cisco.com>
 @date 2015 May 8
*/

#include <linux/kernel.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <stdarg.h>
#include "amp_log.h"

/* Globals: */

static amp_log_level_t _max_log_level = AMP_LOG_NOTICE;

/* Functions: */

void amp_log(amp_log_level_t log_level, const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    if (log_level <= _max_log_level) {
        (void)vprintk(fmt, args);
    }
    va_end(args);
}

void amp_log_set_max_level(amp_log_level_t max_log_level)
{
#ifdef AMP_DEBUG
    _max_log_level = max_log_level;
#else
    _max_log_level = max_log_level < AMP_LOG_INFO ? max_log_level : AMP_LOG_INFO;
#endif
}

char *amp_addr_to_str(const struct sockaddr *addr, char *str, size_t str_size)
{
    if (!str || str_size < 1) {
        goto done;
    }
    str[0] = '\0';
    if (addr->sa_family == AF_INET) {
#ifndef NIPQUAD
        snprintf(str, str_size,
                 "%pI4",
                 &((struct sockaddr_in *)addr)->sin_addr);
#else
        snprintf(str, str_size,
                 NIPQUAD_FMT,
                 NIPQUAD(((struct sockaddr_in *)addr)->sin_addr));
#endif
    } else if (addr->sa_family == AF_INET6) {
#ifndef NIP6_FMT
        snprintf(str, str_size,
                 "%pI6",
                 &((struct sockaddr_in6 *)addr)->sin6_addr);
#else
        snprintf(str, str_size,
                 NIP6_FMT,
                 NIP6(((struct sockaddr_in6 *)addr)->sin6_addr));
#endif
    }
done:
    return str;
}

