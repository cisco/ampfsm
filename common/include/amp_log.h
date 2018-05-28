/**
 @brief AMP Kernel Logger
        Copyright 2015-2018 Cisco Systems
        GNU Public License
 @author Craig Davison <crdaviso@cisco.com>
 @date 2015 May 8
*/

#include <linux/socket.h>

typedef enum {
    AMP_LOG_EMERG,
    AMP_LOG_ALERT,
    AMP_LOG_CRIT,
    AMP_LOG_ERR,
    AMP_LOG_WARNING,
    AMP_LOG_NOTICE,
    AMP_LOG_INFO,
    AMP_LOG_DEBUG
} amp_log_level_t;

void amp_log(amp_log_level_t log_level, const char *fmt, ...);
void amp_log_set_max_level(amp_log_level_t max_log_level);
char *amp_addr_to_str(const struct sockaddr *addr, char *str, size_t str_size);

/* use KERN_INFO for debug, info, notice, warning and err. levels <= KERN_NOTICE
   log to the console, and KERN_DEBUG does not show up in the log. */
#define AMP_LOG_PREFIX_EMERG   KERN_EMERG KBUILD_MODNAME ": <emerg> "
#define AMP_LOG_PREFIX_ALERT   KERN_ALERT KBUILD_MODNAME ": <alert> "
#define AMP_LOG_PREFIX_CRIT    KERN_CRIT  KBUILD_MODNAME ": <crit> "
#define AMP_LOG_PREFIX_ERR     KERN_INFO  KBUILD_MODNAME ": <error> "
#define AMP_LOG_PREFIX_WARNING KERN_INFO  KBUILD_MODNAME ": <warning> "
#define AMP_LOG_PREFIX_NOTICE  KERN_INFO  KBUILD_MODNAME ": <notice> "
#define AMP_LOG_PREFIX_INFO    KERN_INFO  KBUILD_MODNAME ": <info> "
#define AMP_LOG_PREFIX_DEBUG   KERN_INFO  KBUILD_MODNAME ": <debug> "

#define amp_log_emerg(fmt,...) \
    amp_log(AMP_LOG_EMERG, AMP_LOG_PREFIX_EMERG "%s: " fmt "\n", __func__, ##__VA_ARGS__);
#define amp_log_alert(fmt,...) \
    amp_log(AMP_LOG_ALERT, AMP_LOG_PREFIX_ALERT "%s: " fmt "\n", __func__, ##__VA_ARGS__);
#define amp_log_crit(fmt,...) \
    amp_log(AMP_LOG_CRIT, AMP_LOG_PREFIX_CRIT "%s: " fmt "\n", __func__, ##__VA_ARGS__);
#define amp_log_err(fmt,...) \
    amp_log(AMP_LOG_ERR, AMP_LOG_PREFIX_ERR "%s: " fmt "\n", __func__, ##__VA_ARGS__);
#define amp_log_warning(fmt,...) \
    amp_log(AMP_LOG_WARNING, AMP_LOG_PREFIX_WARNING "%s: " fmt "\n", __func__, ##__VA_ARGS__);
#define amp_log_notice(fmt,...) \
    amp_log(AMP_LOG_NOTICE, AMP_LOG_PREFIX_NOTICE "%s: " fmt "\n", __func__, ##__VA_ARGS__);
#define amp_log_info(fmt,...) \
    amp_log(AMP_LOG_INFO, AMP_LOG_PREFIX_INFO "%s: " fmt "\n", __func__, ##__VA_ARGS__);
#define amp_log_debug(fmt,...) \
    amp_log(AMP_LOG_DEBUG, AMP_LOG_PREFIX_DEBUG "%s: " fmt "\n", __func__, ##__VA_ARGS__);
