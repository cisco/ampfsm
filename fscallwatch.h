/**
 * @brief File Call Watch (FCW) API
 *        Copyright 2016-2018 Cisco Systems
 *        GNU Public License
 */
#ifndef FSCALLWATCH_H
#define FSCALLWATCH_H

#include "fsm.h"

/**
 * @brief File operation callback. Called after a file-system sys call has been
 *        processed and all the information loaded into the amp_fsm_op_data_t
 *        struct.
 *
 * @param[in] data - File operation information
 *
 * return @todo (currently not used)
 */
typedef int (*fcw_op_cb_t)(fileop_data_t *data);

typedef struct {
    fcw_op_cb_t op;
} fcw_cb_t;

/**
 * @brief Register file-system sys call watchers (kprobes).
 *
 * @param[in] cb - pointer to a structure defining callbacks
 * @param[in] filter - File operations to accept
 *
 * @return 0 if successful, or nonzero on error
 */
int fcw_init(fcw_cb_t *cb, amp_fsm_op_t filter);

/**
 * @brief Unregister file-system sys call watchers.
 *
 * @return 0 if successful, or nonzero on error
 */
int fcw_deinit(void);

/**
 * @brief Set file operation filter.
 *
 * @param[in] filter - File operations to accept
 *
 * @return 0 on success or -1 if file callwatcher is not initialized
 */
int fcw_set_filter(amp_fsm_op_t filter);

#endif
