/**
 * @brief File Call Watch (FCW) API
 *        Copyright 2016-2018 Cisco Systems
 *        GNU Public License
 */
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/net.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/syscalls.h>
#include <uapi/linux/fcntl.h>

#include "compat.h"
#include "amp_log.h"
#include "fsm.h"
#include "fscallwatch.h"

#define FCW_KRETPROBE_MAXACTIVE (20)
#define FCW_PROBE_LIST_SIZE     (10) /* Store 10 jprobe events at a time */
#define INVALID_TID             (-1) /* A thread ID inside the kernel can
                                        never be 0 or -1. We use -1 to represent
                                        an invalid or missing thread ID. */

enum {
    FCW_PROBE_SYS_RENAME_IDX = 0,
    FCW_PROBE_SYS_RENAMEAT_IDX,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,15,0)
    FCW_PROBE_SYS_RENAMEAT2_IDX,
#endif
    FCW_PROBE_COUNT,
};

struct _jprobe_elem {
    int registered;
    struct jprobe probe;
};

struct _kretprobe_elem {
    int registered;
    struct kretprobe probe;
};

struct _event_elem {
    pid_t tid;
    fileop_data_t *fileop;
};

struct _probe_elem {
    amp_fsm_op_t op;
    struct _kretprobe_elem k;
    struct _jprobe_elem j;
    struct _event_elem events[FCW_PROBE_LIST_SIZE];
    spinlock_t events_lock;
};

struct state {
    int initialized;
    amp_fsm_op_t filter;
    fcw_cb_t cb;
    struct _probe_elem probes[FCW_PROBE_COUNT];
};

/**
 * @brief Called from a jprobe handler. Collects as much information about the
 *        process invoking the sys call and stores it in a buffer to wait for
 *        it's matching kretprobe.
 *
 * @param[in] probe_idx - Probe index
 * @param[in] olddirfd - File descriptor of the directory where the file is
 *                       moving from
 * @param[in] oldpath - Relative or absolute path of the original file
 * @param[in] newdirfd - File descriptor of the directory where the file is
 *                       moving to
 * @param[in] newpath - Relative or absolute path of the new file
 * @param[in] flags - As described in `man renameat`
 */
static void _op_pre_process(int probe_idx,
                            int olddirfd, const char __user *oldpath,
                            int newdirfd, const char __user *newpath,
                            int flags);

/**
 * @brief Called from a kretprobe handler. Finds a matching jprobe event and,
 *        if one is found, the event is added to a work queue to be sent to
 *        any interested clients.
 *
 * @param[in] probe_idx - Probe index
 * @param[in] ret - Return code from kretprobe (sys call)
 */
static void _op_post_process(int probe_idx, int ret);

/**
 * @brief Add a fileop_data_t to the send work queue.
 *
 * @details When this function returns success (0) the memory for fileop_data_t
 *          is passed to the work queue and it should not be released.
 *
 * @param[in] data - Pointer to a fileop_data_t struct
 *
 * @return 0 if data was queued successfully or -1 on error
 */
static int _op_send(fileop_data_t *data);

/**
 * @brief jprobe handler for the `rename` sys call. The event will be stored in
 *        a fixed size array to wait for its corresponding kretprobe to retrieve
 *        the return code.
 *
 * @param[in] oldpath - Relative or absolute path of the original file in user
 *                      address space
 * @param[in] newpath - Relative or absolute path of the new file in user
 *                      address space
 */
static void _rename_handler(const char __user *oldpath, const char __user *newpath);

/**
 * @brief jprobe handler for the `renameat` sys call. The event will be stored
 *        in a fixed size array to wait for its corresponding kretprobe to
 *        retrieve the return code.
 *
 * @param[in] olddirfd - File descriptor of the directory where the file is
 *                       moving from
 * @param[in] oldpath - Relative or absolute path of the original file in user
 *                      address space
 * @param[in] newdirfd - File descriptor of the directory where the file is
 *                       moving to
 * @param[in] newpath - Relative or absolute path of the new file in user
 *                      address space
 */
static void _renameat_handler(int olddirfd, const char __user *oldpath,
                              int newdirfd, const char __user *newpath);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,15,0)
/**
 * @brief jprobe handler for the `renameat2` sys call. The event will be stored
 *        in a fixed size array to wait for its corresponding kretprobe to
 *        retrieve the return code.
 *
 * @param[in] olddirfd - File descriptor of the directory where the file is
 *                       moving from
 * @param[in] oldpath - Relative or absolute path of the original file in user
 *                      address space
 * @param[in] newdirfd - File descriptor of the directory where the file is
 *                       moving to
 * @param[in] newpath - Relative or absolute path of the new file in user
 *                      address space
 * @param[in] flags - As described in `man renameat2`
 */
static void _renameat2_handler(int olddirfd, const char __user *oldpath,
                               int newdirfd, const char __user *newpath, int flags);
#endif

/**
 * @brief kretprobe handler for the `rename` sys call. A matching jprobe event
 *        will be fetched from a buffer by the current process ID. If no
 *        matching jprobe event is found we can assume that the jprobe event
 *        occurred before the module was initialized and the event kretprobe
 *        event will be dropped.
 *
 * @param[in] ri - Pointer to current kretprobe instance
 * @param[in] regs - Saved registers
 *
 * @return 0
 */
static int _rename_post_handler(struct kretprobe_instance *ri,
                                struct pt_regs *regs);

/**
 * @brief kretprobe handler for the `renameat` sys call. A matching jprobe event
 *        will be fetched from a buffer by the current process ID. If no
 *        matching jprobe event is found we can assume that the jprobe event
 *        occurred before the module was initialized and the event kretprobe
 *        event will be dropped.
 *
 * @param[in] ri - Pointer to current kretprobe instance
 * @param[in] regs - Saved registers
 *
 * @return 0
 */
static int _renameat_post_handler(struct kretprobe_instance *ri,
                                  struct pt_regs *regs);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,15,0)
/**
 * @brief kretprobe handler for the `renameat2` sys call. A matching jprobe
 *        event will be fetched from a buffer by the current process ID. If no
 *        matching jprobe event is found we can assume that the jprobe event
 *        occurred before the module was initialized and the event kretprobe
 *        event will be dropped.
 *
 * @param[in] ri - Pointer to current kretprobe instance
 * @param[in] regs - Saved registers
 *
 * @return 0
 */
static int _renameat2_post_handler(struct kretprobe_instance *ri,
                                   struct pt_regs *regs);
#endif

/**
 * @brief Find event with matching thread ID and return the index.
 *
 * @param[in] tid - Thread ID to look for
 * @param[in] events - Array of events
 * @param[in] event_size - Number of elements in event array
 *
 * @return Index of event with matching thread ID or -1 if not found
 */
static int _events_find_tid_index(pid_t tid,
                                  struct _event_elem events[],
                                  size_t event_size);

/**
 * @brief Find a free slot in the event array.
 *
 * @param[in] events - Array of events
 * @param[in] event_size - Number of elements in event array
 *
 * @return Index of free slot or -1 if event array is full
 */
static int _events_find_free_index(struct _event_elem events[],
                                   size_t event_size);

/**
 * @brief Initialize event array with default values.
 *
 * @param[in] events - Array of events
 * @param[in] event_size - Number of elements in event array
 */
static void _events_init(struct _event_elem events[], size_t event_size);

/**
 * @brief Reset each event array slot and return the number of dropped events.
 *
 * @param[in] events - Array of events
 * @param[in] event_size - Number of elements in event array
 *
 * @return number of dropped events
 */
static size_t _events_reset(struct _event_elem events[], size_t event_size);

static struct state _state = {
    .probes = {
        {
            .op = AMP_FSM_OP_RENAME,
            .j.probe.kp.symbol_name = "sys_rename",
            .j.probe.entry = _rename_handler,
            .k.probe.kp.symbol_name = "sys_rename",
            .k.probe.handler = _rename_post_handler,
            .k.probe.maxactive = FCW_KRETPROBE_MAXACTIVE,
        },
        {
            .op = AMP_FSM_OP_RENAME,
            .j.probe.kp.symbol_name = "sys_renameat",
            .j.probe.entry = _renameat_handler,
            .k.probe.kp.symbol_name = "sys_renameat",
            .k.probe.handler = _renameat_post_handler,
            .k.probe.maxactive = FCW_KRETPROBE_MAXACTIVE,
        },
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,15,0)
        {
            .op = AMP_FSM_OP_RENAME,
            .j.probe.kp.symbol_name = "sys_renameat2",
            .j.probe.entry = _renameat2_handler,
            .k.probe.kp.symbol_name = "sys_renameat2",
            .k.probe.handler = _renameat2_post_handler,
            .k.probe.maxactive = FCW_KRETPROBE_MAXACTIVE,
        },
#endif
    }
};

static int _events_find_tid_index(pid_t tid,
                                  struct _event_elem events[],
                                  size_t event_size)
{
    int index = -1;
    size_t i;

    for (i = 0; i < event_size; i++) {
        if (events[i].tid == tid) {
            index = i;
            break;
        }
    }

    return index;
}

static int _events_find_free_index(struct _event_elem events[],
                                   size_t event_size)
{
    int index = -1;
    size_t i;

    for (i = 0; i < event_size; i++) {
        if (events[i].tid == INVALID_TID) {
            index = i;
            break;
        }
    }

    return index;
}

static void _events_init(struct _event_elem events[], size_t event_size)
{
    size_t i;

    for (i = 0; i < event_size; i++) {
        events[i].fileop = NULL;
        events[i].tid = INVALID_TID;
    }
}

static size_t _events_reset(struct _event_elem events[], size_t event_size)
{
    size_t i;
    size_t dropped_events = 0;

    for (i = 0; i < event_size; i++) {
        if (events[i].fileop) {
            fileop_free(events[i].fileop);
            events[i].fileop = NULL;
            dropped_events++;
        }
        events[i].tid = INVALID_TID;
    }

    return dropped_events;
}

static void _op_pre_process(int probe_idx,
                            int olddirfd, const char __user *oldpath,
                            int newdirfd, const char __user *newpath,
                            int flags)
{
    fileop_data_t *data;
    int free_idx;
    int locked = 0;

    (void) olddirfd;
    (void) oldpath;
    (void) flags;

    if (!_state.initialized) {
        goto done;
    }

    if (!(_state.filter & _state.probes[probe_idx].op)) {
        amp_log_debug("[jprobe][tid:%d][probe:%d] Event not in filter, dropping...",
                      task_pid_nr(current), probe_idx);
        goto done;
    }

    spin_lock(&_state.probes[probe_idx].events_lock);
    locked = 1;
    free_idx = _events_find_free_index(_state.probes[probe_idx].events,
                                       ARRAY_SIZE(_state.probes[probe_idx].events));
    if (free_idx < 0) {
        amp_log_err("_events_find_free_index failed, dropping...");
        goto done;
    }

    amp_log_debug("[jprobe][tid:%d][probe:%d] Found free slot: %d",
                  task_pid_nr(current), probe_idx, free_idx);

    data = fileop_new(_state.probes[probe_idx].op, newdirfd, newpath);
    /* fileop_new will log on error. When fileop_new fails we save the event
       as the kretprobe handler will be expecting a matching thread ID event. */
    _state.probes[probe_idx].events[free_idx].tid = task_pid_nr(current);
    _state.probes[probe_idx].events[free_idx].fileop = data;
done:
    if (locked) {
        spin_unlock(&_state.probes[probe_idx].events_lock);
        locked = 0;
    }
}

static void _op_post_process(int probe_idx, int ret)
{
    int pid_idx;
    int locked = 0;
    fileop_data_t *fileop = NULL;

    if (!_state.initialized) {
        goto done;
    }

    if (!(_state.filter & _state.probes[probe_idx].op)) {
        amp_log_debug("[kretprobe][tid:%d][probe:%d] Event not in filter, dropping...",
                      task_pid_nr(current), probe_idx);
        goto done;
    }

    spin_lock(&_state.probes[probe_idx].events_lock);
    locked = 1;
    pid_idx = _events_find_tid_index(task_pid_nr(current),
                                     _state.probes[probe_idx].events,
                                     ARRAY_SIZE(_state.probes[probe_idx].events));
    if (pid_idx < 0) {
        amp_log_err("[kretprobe][tid:%d][probe:%d] Matching event not found, "
                    "dropping...",  task_pid_nr(current), probe_idx);
        goto done;
    }

    /* Reset event slot and release lock */
    fileop = _state.probes[probe_idx].events[pid_idx].fileop;
    _state.probes[probe_idx].events[pid_idx].tid = -1;
    _state.probes[probe_idx].events[pid_idx].fileop = NULL;
    spin_unlock(&_state.probes[probe_idx].events_lock);
    locked = 0;

    if (!fileop) {
        /* Either we were unable to allocate memory for the event or parameters
         * to the syscall were invalid. A log message would have been printed
         * in the _op_pre_process handler for both cases so we can silently quit
         * here. */
        goto done;
    }

    amp_log_debug("[kretprobe][tid:%d][probe:%d] Found event: %d",
                  task_pid_nr(current), probe_idx, pid_idx);

    /* If the return code is 0 (success) we attempt to build an absolute path
     * from the stored sys call arguments and normalize it. */
    if (ret != 0) {
        amp_log_info("[kretprobe][tid:%d][probe:%d] Return code non-zero (%d), "
                     "dropping...",  task_pid_nr(current), probe_idx, ret);
        goto done;
    }

    if (fileop_set_path(fileop) != 0) {
        amp_log_err("fileop_set_path failed, dropping...");
        goto done;
    }

    if (_op_send(fileop) != 0) {
        amp_log_err("Failed to queue event, dropping...");
        goto done;
    }
    /* Passed off to workqueue */
    fileop = NULL;
done:
    if (locked) {
        spin_unlock(&_state.probes[probe_idx].events_lock);
        locked = 0;
    }

    if (fileop) {
        fileop_free(fileop);
        fileop = NULL;
    }
}

static int _op_send(fileop_data_t *data)
{
    int ret = -1;

    if (!data || !_state.initialized || !_state.cb.op) {
        goto done;
    }

    (void)_state.cb.op(data);
    /* Pass data off */
    data = NULL;
    ret = 0;
done:
    return ret;
}

static void _rename_handler(const char __user *oldpath, const char __user *newpath)
{
    _op_pre_process(FCW_PROBE_SYS_RENAME_IDX,
                    AT_FDCWD, oldpath, AT_FDCWD, newpath, 0);
    jprobe_return();
}

static void _renameat_handler(int olddirfd, const char __user *oldpath,
                              int newdirfd, const char __user *newpath)
{
    _op_pre_process(FCW_PROBE_SYS_RENAMEAT_IDX,
                    olddirfd, oldpath, newdirfd, newpath, 0);
    jprobe_return();
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,15,0)
static void _renameat2_handler(int olddirfd, const char __user *oldpath,
                               int newdirfd, const char __user *newpath, int flags)
{
    _op_pre_process(FCW_PROBE_SYS_RENAMEAT2_IDX,
                    olddirfd, oldpath, newdirfd, newpath, flags);
    jprobe_return();
}
#endif

static int _rename_post_handler(struct kretprobe_instance *ri,
                                struct pt_regs *regs)
{
    _op_post_process(FCW_PROBE_SYS_RENAME_IDX, regs_return_value(regs));
    return 0;
}

static int _renameat_post_handler(struct kretprobe_instance *ri,
                                  struct pt_regs *regs)
{
    _op_post_process(FCW_PROBE_SYS_RENAMEAT_IDX, regs_return_value(regs));
    return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,15,0)
static int _renameat2_post_handler(struct kretprobe_instance *ri,
                                   struct pt_regs *regs)
{
    _op_post_process(FCW_PROBE_SYS_RENAMEAT2_IDX, regs_return_value(regs));
    return 0;
}
#endif

int fcw_init(fcw_cb_t *cb, amp_fsm_op_t filter)
{
    int ret = 0;
    size_t probe_idx;

    if (_state.initialized || !cb || !cb->op) {
        ret = -EINVAL;
        goto done;
    }

    for (probe_idx = 0; probe_idx < FCW_PROBE_COUNT; probe_idx++) {
        struct _probe_elem *probe = &_state.probes[probe_idx];

        spin_lock_init(&probe->events_lock);

        ret = register_jprobe(&probe->j.probe);
        if (ret != 0) {
            goto unregister;
        }
        probe->j.registered = 1;
        amp_log_debug("[probe:%d] registered jprobe", probe_idx);

        ret = register_kretprobe(&probe->k.probe);
        if (ret != 0) {
            goto unregister;
        }
        probe->k.registered = 1;
        amp_log_debug("[probe:%d] registered kretprobe", probe_idx);

        _events_init(probe->events, ARRAY_SIZE(probe->events));

    }

    _state.filter = filter;
    _state.cb = *cb;
    _state.initialized = 1;
    goto done;
unregister:
    (void) fcw_deinit();
done:
    return ret;
}

int fcw_deinit(void)
{
    int ret = 0;
    size_t probe_idx, dropped_events = 0;
    struct _probe_elem *probe;

    for (probe_idx = 0; probe_idx < FCW_PROBE_COUNT; probe_idx++) {
        probe = &_state.probes[probe_idx];

        if (probe->j.registered) {
            unregister_jprobe(&probe->j.probe);
            probe->j.registered = 0;
            amp_log_debug("[probe:%d] unregistered jprobe", probe_idx);
        }

        if (probe->k.registered) {
            unregister_kretprobe(&probe->k.probe);
            probe->k.registered = 0;
            amp_log_debug("[probe:%d] unregistered kretprobe", probe_idx);
        }

        dropped_events = _events_reset(probe->events, ARRAY_SIZE(probe->events));

        amp_log_debug("[probe:%d] cleaned up %zu events", probe_idx,
                      dropped_events);
    }

    _state.filter = 0;
    memset(&_state.cb, 0, sizeof(fcw_cb_t));
    _state.initialized = 0;

    return ret;
}

int fcw_set_filter(amp_fsm_op_t filter)
{
    int ret = -1;

    if (_state.initialized) {
        _state.filter = filter;
        ret = 0;
    }

    return ret;
}
