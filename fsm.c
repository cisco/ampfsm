/**
 * @brief File Operation Module
 *        Copyright 2016-2018 Cisco Systems
 *        GNU Public License
 */
#include "compat.h"
#include "amp_log.h"
#include "fsm.h"
#include "fscallwatch.h"
#include "include/comm.h"

#include <linux/module.h>
#include <linux/version.h>
#include <linux/syscalls.h>
#include <linux/string.h>
#include <linux/file.h>
#include <linux/mount.h>
#include <linux/sched.h>
#include <linux/fs_struct.h>
#include <linux/string.h>
#include <net/genetlink.h>
#include <linux/fdtable.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Russ Kubik");
MODULE_AUTHOR("Craig Davison");
MODULE_AUTHOR("Cisco <tac@cisco.com>");

/**
 * AMP_RELEASE_KMOD is defined if the kernel module is compiled in an
 * official Connector release.
 * AMP_CUSTOM_KMOD is defined if the kernel module is compiled by a user.
 * It contains a custom identifier for the kernel module.
 */
#ifdef AMP_RELEASE_KMOD
    MODULE_DESCRIPTION("Cisco AMP Filesystem Module");
#else
#ifdef AMP_CUSTOM_KMOD
    MODULE_DESCRIPTION("Cisco AMP Filesystem Module (user-built) " AMP_CUSTOM_KMOD);
#else
    MODULE_DESCRIPTION("Cisco AMP Filesystem Module (user-built)");
#endif
#endif

static struct {
    /* nl_portid - only send messages to this peer, and do not send at all if
     *             it is 0.
     * set nl_portid whenever a message is received from userland, and reset it
     * to 0 if send fails. since only root can send a message, this ensures
     * that the peer is a process owned by root. */
    uint32_t nl_portid;
    struct mutex portid_mutex;
    atomic_t num_rec_queued;
    struct workqueue_struct *msg_send_wq;
    struct kmem_cache *path_kmem_cache;
    struct kmem_cache *fileop_data_kmem_cache;
    int is_fcw_init; /* Filesystem call watcher initialized? */
    int is_nl_reg; /* Netlink family registered? */
} _state = {
    .num_rec_queued = ATOMIC_INIT(0),
};

static struct genl_family _g_genl_family = {
#ifdef GENL_ID_GENERATE
    .id = GENL_ID_GENERATE,
#endif
    .hdrsize = 0,
    .name = AMP_FSM_GENL_FAM_NAME,
    .version = AMP_FSM_GENL_VERSION,
    .maxattr = AMP_FSM_ATTR_COUNT-1,
};

static struct nla_policy _g_cmd_set_opts_pol[AMP_FSM_ATTR_COUNT] __read_mostly = {
    [AMP_FSM_ATTR_LOG_LEVEL] = {
        .type = NLA_U8
    },
    [AMP_FSM_ATTR_FILEOP_FILTER] = {
        .type = NLA_U32
    },
};

static struct nla_policy _g_no_attrs_pol[AMP_FSM_ATTR_COUNT] __read_mostly = {
};

/**
 * @brief Convert a file operation type to string.
 *
 * @param[in] op - File operation
 *
 * @return String representation of file operation
 */
static const char *_fileop_name(amp_fsm_op_t op);

/**
 * @brief Netlink handler for setting options.
 *
 * @param[in] skb - Socket buffer
 * @param[in] info - Netlink information
 *
 * @return 0
 */
static int _set_opts(struct sk_buff *skb, struct genl_info *info);

/**
 * @brief Initial message sent from user-space program to kernel to initiate
 *        filesystem event monitoring.
 *
 * @param[in] skb - Socket buffer
 * @param[in] info - Netlink information
 *
 * @return 0
 */
static int _hello(struct sk_buff *skb, struct genl_info *info);

/**
 * @brief Update the current port ID (peer information).
 *
 * @param[in] info - Netlink information
 *
 * @return 0 on success, or errno on error
 */
static int _update_portid(struct genl_info *info);

/**
 * @brief Work queue worker task. The given fileop_data_t structure will be
 *        sent to any interested netlink clients.
 *
 * @param[in] data - File operation data structure
 */
static inline void __msg_send_task(fileop_data_t *data);

#ifdef INIT_WORK_USES_CONTAINER
/**
 * @brief Wrapper around __msg_send_task with kernel containerof support.
 *
 * @param[in] work - Work queue structure
 */
static void _msg_send_task(struct work_struct *work);
#else
/**
 * @brief Wrapper around __msg_send_task without kernel containerof support.
 *
 * @param[in] work - Work queue structure
 */
static void _msg_send_task(void *param);
#endif

/**
 * @brief Send an AMP_FSM_CMD_REC_HELLO signal to userland to
 *        signal successful communication link.
 */
static void _msg_send_hello_rec(void);

/**
 * @brief File operation callback from the FS call watch API. Any events that
 *        do not match the filter (given by fscw_set_filter) will be dropped
 *        prior to this callback.
 *
 * @param[in] data - File operation structure
 */
static void _op_cb(fileop_data_t *data);

/**
 * @brief Construct a path from the base path (data->pwd) and the file path from the rename system call.
 *
 * @param[out] buf - buffer to write the output path to
 * @param[in] buf_size - size of output buffer
 * @param[in] pwd - working directory
 * @param[in] op_path - file path supplied for the operation
 *
 * @return 0 on success, -1 on error
 */
static int _build_path(char* buf, size_t buf_size, const struct path * pwd, const char * op_path);

static struct genl_ops _g_genl_ops[] = {
    {
        .cmd     = AMP_FSM_CMD_SET_OPTS,
        .flags   = GENL_ADMIN_PERM,
        .policy  = _g_cmd_set_opts_pol,
        .doit    = _set_opts,
    },
    {
        .cmd     = AMP_FSM_CMD_HELLO,
        .flags   = GENL_ADMIN_PERM,
        .policy  = _g_no_attrs_pol,
        .doit    = _hello,
    },
};

static const char *_fileop_name(amp_fsm_op_t op)
{
    const char *str = NULL;

    if (op == AMP_FSM_OP_RENAME) {
        str = "rename";
    }

    return str;
}

static int _set_opts(struct sk_buff *skb, struct genl_info *info)
{
    uint8_t log_level;
    amp_fsm_op_t fileop_filter;

    if (_update_portid(info) != 0) {
        goto done;
    }

    log_level = nla_get_u8(info->attrs[AMP_FSM_ATTR_LOG_LEVEL]);
    amp_log_set_max_level(log_level);
    amp_log_info("AMP_FSM_ATTR_LOG_LEVEL = %u", log_level);

    fileop_filter = nla_get_u32(info->attrs[AMP_FSM_ATTR_FILEOP_FILTER]);
    fcw_set_filter(fileop_filter);
    amp_log_info("AMP_FSM_ATTR_FILEOP_FILTER = %u", fileop_filter);
done:
    return 0;
}

static int _hello(struct sk_buff *skb, struct genl_info *info)
{
    (void)_update_portid(info);
    _msg_send_hello_rec();
    return 0;
}

static int _update_portid(struct genl_info *info)
{
    int ret = 0;

    if (info->genlhdr->version != AMP_FSM_GENL_VERSION) {
        amp_log_info("info->genlhdr->version %d != %d",
                     info->genlhdr->version, AMP_FSM_GENL_VERSION);
        ret = -EINVAL;
        goto done;
    }

    mutex_lock(&_state.portid_mutex);
#ifdef NETLINK_USES_PORTID
    _state.nl_portid = info->snd_portid;
#else
    /* old nomenclature: pid */
    _state.nl_portid = info->snd_pid;
#endif
    mutex_unlock(&_state.portid_mutex);
done:
    return ret;
}

static inline void _msg_send_hello_rec()
{
    int err;
    struct sk_buff *skb = NULL;
    void *genl_msg;

    skb = alloc_skb(SKB_MAX_ALLOC, GFP_KERNEL);
    if (!skb) {
        amp_log_err("alloc_skb failed");
        goto done;
    }

    genl_msg = GENLMSG_PUT(skb,
                           0, /* portid */
                           0, /* sequence number*/
                           &_g_genl_family,
                           0 /* flags */,
                           AMP_FSM_CMD_REC_HELLO);
    if (genl_msg == NULL) {
        amp_log_err("genlmsg_put failed");
        goto done;
    }

    (void)genlmsg_end(skb, genl_msg);

    mutex_lock(&_state.portid_mutex);

    if (_state.nl_portid != 0) {
        err = GENLMSG_UNICAST(&init_net, skb, _state.nl_portid);
        /* don't free skb after handing it off to genlmsg_unicast, even if
           the function returns an error */
        skb = NULL;
        /* genlmsg_unicast returns -ECONNREFUSED if there are no listeners, and
           -EAGAIN if the listener's buffer is full */
        if (err != 0) {
            if (err == -ECONNREFUSED) {
                /* peer disconnected */
                amp_log_info("peer disconnected");
                _state.nl_portid = 0;
            } else if (err == -EAGAIN) {
                amp_log_info("dropped msg");
            } else {
                amp_log_err("genlmsg_unicast failed: %d", err);
            }
        }
    }

    mutex_unlock(&_state.portid_mutex);
done:
    if (skb) {
        nlmsg_free(skb);
        skb = NULL;
    }
}

static inline void __msg_send_task(fileop_data_t *data)
{
    int data_pwd_valid = 1;
    int err;
    struct sk_buff *skb = NULL;
    void *genl_msg;
    amp_fsm_op_t op;
    pid_t pid;
    pid_t ppid;
    uid_t uid;

    /* Combined path is the working directory combined with the operation's
     * specified file path */
    char *combined_path = kmem_cache_alloc(_state.path_kmem_cache, GFP_KERNEL);
    if (!combined_path) {
        amp_log_err("kmem_cache_alloc(path_kmem_cache) failed");
        goto done;
    }

    err = _build_path(combined_path, PATH_MAX, &data->pwd, data->path);

    /* path_put may sleep */
    path_put(&data->pwd);
    data_pwd_valid = 0;

    if (err) {
        amp_log_err("_build_path failed, dropping...");
        goto done;
    }

    /* Copy information from input fileop to local variables to expedite
     * freeing allocated memory */
    op = data->op;
    uid = data->uid;
    pid = data->pid;
    ppid = data->ppid;

    fileop_free(data);
    data = NULL;

    skb = alloc_skb(SKB_MAX_ALLOC, GFP_KERNEL);
    if (!skb) {
        amp_log_err("alloc_skb failed");
        goto done;
    }

    genl_msg = GENLMSG_PUT(skb,
                           0, /* portid */
                           0, /* sequence number, 0 for events */
                           &_g_genl_family,
                           0 /* flags */,
                           AMP_FSM_CMD_REC_OP);
    if (genl_msg == NULL) {
        amp_log_err("genlmsg_put failed");
        goto done;
    }

    err = nla_put_u32(skb, AMP_FSM_ATTR_REC_OP, op);
    if (err != 0) {
        amp_log_err("nla_put_u8(op) failed");
        goto done;
    }

    err = nla_put_u32(skb, AMP_FSM_ATTR_REC_UID, uid);
    if (err != 0) {
        amp_log_err("nla_put_u32(uid) failed");
        goto done;
    }

    err = nla_put_u32(skb, AMP_FSM_ATTR_REC_PID, pid);
    if (err != 0) {
        amp_log_err("nla_put_u32(pid) failed");
        goto done;
    }

    err = nla_put_u32(skb, AMP_FSM_ATTR_REC_PPID, ppid);
    if (err != 0) {
        amp_log_err("nla_put_u32(ppid) failed");
        goto done;
    }

    err = nla_put_string(skb, AMP_FSM_ATTR_REC_PATH, combined_path);
    if (err != 0) {
        amp_log_err("nla_put_string(path) failed");
        goto done;
    }

    (void)genlmsg_end(skb, genl_msg);

    kmem_cache_free(_state.path_kmem_cache, combined_path);
    combined_path = NULL;

    mutex_lock(&_state.portid_mutex);

    if (_state.nl_portid != 0) {
        err = GENLMSG_UNICAST(&init_net, skb, _state.nl_portid);
        /* don't free skb after handing it off to genlmsg_unicast, even if
           the function returns an error */
        skb = NULL;
        /* genlmsg_unicast returns -ECONNREFUSED if there are no listeners, and
           -EAGAIN if the listener's buffer is full */
        if (err != 0) {
            if (err == -ECONNREFUSED) {
                /* peer disconnected */
                amp_log_info("peer disconnected");
                _state.nl_portid = 0;
            } else if (err == -EAGAIN) {
                amp_log_info("dropped msg");
            } else {
                amp_log_err("genlmsg_unicast failed: %d", err);
            }
        }
    }

    mutex_unlock(&_state.portid_mutex);

done:
    if (skb) {
        nlmsg_free(skb);
        skb = NULL;
    }
    if (combined_path) {
        kmem_cache_free(_state.path_kmem_cache, combined_path);
        combined_path = NULL;
    }
    if (data_pwd_valid) {
        path_put(&data->pwd);
        data_pwd_valid = 0;
    }
    fileop_free(data);
    data = NULL;

    atomic_dec(&_state.num_rec_queued);
}

#ifdef INIT_WORK_USES_CONTAINER
static void _msg_send_task(struct work_struct *work)
{
    fileop_data_t *data = container_of(work, fileop_data_t, work);
    __msg_send_task(data);
}
#else
static void _msg_send_task(void *param)
{
    fileop_data_t *data = param;
    __msg_send_task(data);
}
#endif

static void _op_cb(fileop_data_t *data)
{
    const char *event_name = _fileop_name(data->op);

    atomic_inc(&_state.num_rec_queued);

    amp_log_info("op: %s, path: %s, pid: %d, ppid: %d, uid: %d",
                 event_name ? event_name : "unknown",
                 data->path, data->pid, data->ppid, data->uid);

#ifdef INIT_WORK_USES_CONTAINER
    INIT_WORK(&data->work, _msg_send_task);
#else
    INIT_WORK(&data->work, _msg_send_task, data);
#endif
    (void)queue_work(_state.msg_send_wq, &data->work);
    data = NULL;
}

static int _build_path(char* buf, size_t buf_size, const struct path * pwd, const char * op_path)
{
    int ret = -1;
    char *pwd_ptr = NULL;
    size_t pwd_len = 0;
    size_t op_path_len = 0;

    /* d_path may sleep */
    pwd_ptr = d_path(pwd, buf, buf_size);
    if (!pwd_ptr || (pwd_ptr && IS_ERR(pwd_ptr))) {
        amp_log_err("d_path failed");
        goto done;
    }

    pwd_len = strlen(pwd_ptr);
    op_path_len = strlen(op_path);

    if ((pwd_len + 1 + op_path_len) < buf_size) {
        char *b = buf;

        if (pwd_len > 0) {
            /* d_path does not guarantee placing the result at the beginning
             * of the buffer. If necessary, move the working directory
             * to the start so the full buffer can be used. */
            if (pwd_ptr != buf) {
                memmove(buf, pwd_ptr, pwd_len);
            }

            /* The working directory may have a trailing slash and the
             * operation path may have a leading slash. Avoid duplicating
             * slashes in those cases. If neither string can contribute a
             * delimiter slash then add one. */
            b += pwd_len - 1;
            if (*b == '/') {
                if (*op_path != '/') {
                    b += 1;
                }
            } else {
                if (*op_path != '/') {
                    b += 1;
                    *b++ = '/';
                }
            }
        }

        /* Append the operation file path including null terminator. */
        memcpy(b, op_path, op_path_len + 1);

        ret = 0;
    }
done:
    return ret;
}

fileop_data_t *fileop_new(amp_fsm_op_t op, int dirfd, const char __user *filename)
{
    /* Allocate memory with GFP_NOWAIT to accomodate when preemption is
     * disabled such as in probe handlers. Prefer GFP_NOWAIT over GFP_ATOMIC
     * as occasional allocation failure is acceptable and avoids stressing the
     * kernel. Suppress allocation failure warnings in release mode. */
#ifdef AMP_DEBUG
    const gfp_t gfp_flags = GFP_NOWAIT;
#else
    const gfp_t gfp_flags = GFP_NOWAIT | __GFP_NOWARN;
#endif

    char comm[TASK_COMM_LEN] = { 0 };
    fileop_data_t *data = NULL;
    size_t path_buf_sz = 0;
    long err;
    int success = 0;

    if (!filename) {
        amp_log_info("Null filename given");
        goto done;
    }

    if (access_ok(VERIFY_READ, filename, 1)) {
        char ch;
        if (!get_user(ch, filename)) {
            if (ch == '\0') {
                amp_log_info("Empty filename given");
                goto done;
            }
        }
    }

    data = kmem_cache_alloc(_state.fileop_data_kmem_cache, gfp_flags);
    if (!data) {
        amp_log_err("kmem_cache_alloc(fileop_data) failed");
        goto done;
    }

    /* Allocate memory to copy the "filename" string. Since this function is
     * callable from a probe handler, we avoid calling strnlen_user which can
     * sleep. This presents the challenge of allocating a right-sized buffer
     * before copying.
     *
     * Large memory allocations with GFP_NOWAIT are more likely to fail. To
     * reduce the probabiity of failure, use small buffer optimization on the
     * assumption most file operation paths are much shorter than PATH_MAX.
     * A separate allocation is only needed when the path is long. */
    data->path = data->path_buffer.storage.small_buf;
    data->path_buffer.capacity = 0;
    path_buf_sz = sizeof(data->path_buffer.storage.small_buf);

    err = strncpy_from_user(data->path, filename, path_buf_sz);
    if (err < 0) {
        /* The only failure case where having the current task's comm and tgid is
         * valuable. EFAULT is expected as the userland process can pass any pointer
         * to the system call. */
        if (err == -EFAULT) {
            amp_log_info("strncpy_from_user access to userspace failed (comm: %s, pid: %d)",
                         get_task_comm(comm, current), task_tgid_nr(current));
        } else {
            amp_log_err("strncpy_from_user failed (comm: %s, pid: %d): %ld",
                        get_task_comm(comm, current), task_tgid_nr(current), err);
        }
        goto done;
    } else if (err >= path_buf_sz) {
        /* Path is longer than can be stored in small buffer. Allocate a larger
         * buffer from kernel cache. */
        data->path_buffer.storage.large_buf = kmem_cache_alloc(_state.path_kmem_cache, gfp_flags);
        if (!data->path_buffer.storage.large_buf) {
            amp_log_err("kmem_cache_alloc(path_name) failed");
            goto done;
        }

        data->path = data->path_buffer.storage.large_buf;
        data->path_buffer.capacity = PATH_MAX;
        path_buf_sz = PATH_MAX;

        err = strncpy_from_user(data->path, filename, path_buf_sz);
        if (err < 0) {
            if (err == -EFAULT) {
                amp_log_info("strncpy_from_user 2 access to userspace failed (comm: %s, pid: %d)",
                            get_task_comm(comm, current), task_tgid_nr(current));
            } else {
                amp_log_err("strncpy_from_user 2 failed (comm: %s, pid: %d): %ld",
                            get_task_comm(comm, current), task_tgid_nr(current), err);
            }
            goto done;
        } else if (err >= path_buf_sz) {
            amp_log_err("strncpy_from_user 2; path too long (comm: %s, pid: %d)",
                        get_task_comm(comm, current), task_tgid_nr(current));
            goto done;
        }
    }

    data->path[path_buf_sz - 1] = '\0';
    data->pid = task_tgid_nr(current);
    data->ppid = TASK_PPID_NR(current);
    data->uid = TASK_UID(current);
    data->op = op;
    data->dirfd = dirfd;

    success = 1;

done:
    if (!success) {
        fileop_free(data);
        data = NULL;
    }

    return data;
}

int fileop_set_pwd(fileop_data_t *data)
{
    int ret = -1;
    struct file *file;

    /* Required before accessing current->fs - see the comments for task_lock() */
    task_lock(current);

    if (!data || !data->path || !*data->path || !current->fs) {
        goto done;
    }

    if (data->path[0] == '/') {
        amp_log_debug("Fetching path from root");

        /* For chrooted environments the path given to the syscall may be
         * relative to the chroot root directory. Therefore, a path "/usr/bin/cp"
         * may actually be /var/chroot/usr/bin/cp". */
        get_fs_root(current->fs, &data->pwd);
    } else if (data->dirfd == AT_FDCWD) {
        amp_log_debug("Fetching path from cwd");

        get_fs_pwd(current->fs, &data->pwd);
    } else {
        amp_log_debug("Fetching path from fd: %d", data->dirfd);

        /* fget handles rcu locking of current->files and grabbing a reference
         * to the file handle */
        file = fget(data->dirfd);
        if (!file) {
            /* If the directory is not found then (1) a user may have given
             * a bad fd to the sys call or (2) the directory was moved or
             * deleted. */
            amp_log_info("Directory at fd %d not found", data->dirfd);
            goto done;
        }

        data->pwd = file->f_path;
        path_get(&data->pwd);
        fput(file);
    }

    ret = 0;
done:
    task_unlock(current);
    return ret;
}

void fileop_free(fileop_data_t *data)
{
    if (data) {
        if (data->path_buffer.capacity > 0) {
            kmem_cache_free(_state.path_kmem_cache, data->path_buffer.storage.large_buf);
            data->path_buffer.storage.large_buf = NULL;
        }
        data->path = NULL;

        kmem_cache_free(_state.fileop_data_kmem_cache, data);
        data = NULL;
    }
}

int init_module(void)
{
    int ret = 0;
    int err;
    fcw_cb_t cb = {
        .op = _op_cb
    };

    amp_log_set_max_level(AMP_LOG_NOTICE);
    amp_log_info("starting ampfsm");

    mutex_init(&_state.portid_mutex);

    _state.path_kmem_cache = KMEM_CACHE_CREATE("csco_amp_fcw_path",
        PATH_MAX, 0 /* align */, 0 /* flags */, NULL /* ctor */);
    if (!_state.path_kmem_cache) {
        ret = -ENOMEM;
        goto done;
    }

    _state.fileop_data_kmem_cache = KMEM_CACHE_CREATE("csco_amp_fcw_fileopdata",
        sizeof(fileop_data_t), 0 /* align */, 0 /* flags */, NULL /* ctor */);
    if (!_state.fileop_data_kmem_cache) {
        ret = -ENOMEM;
        goto done;
    }

    /* register generic netlink family */
    err = GENL_REGISTER_FAMILY_WITH_OPS(&_g_genl_family, _g_genl_ops);
    if (err != 0) {
        amp_log_err("GENL_REGISTER_FAMILY_WITH_OPS failed");
        ret = err;
        goto done;
    }
    _state.is_nl_reg = 1;

    amp_log_info("_g_genl_family.id %u", _g_genl_family.id);

    /* initialize work queue */
    _state.msg_send_wq = alloc_workqueue("csco_amp_msg_wq", WQ_MEM_RECLAIM, 0);

    if (!_state.msg_send_wq) {
        amp_log_err("alloc_workqueue(msg_send_wq) failed");
        ret = -ENOMEM;
        goto done;
    }

    /* register filesystem probes */
    err = fcw_init(&cb, AMP_FSM_OP_ALL);
    if (err != 0) {
        ret = err;
        amp_log_err("fcw_init failed");
        goto done;
    }
    _state.is_fcw_init = 1;
done:
    if (ret != 0) {
        cleanup_module();
    }

    return ret;
}

void cleanup_module(void)
{
    int err;
    int num_rec_queued;

    if (_state.is_fcw_init) {
        /* unregister filesystem probes */
        err = fcw_deinit();
        if (err != 0) {
            amp_log_err("fcw_deinit failed (%d)", err);
        }
        _state.is_fcw_init = 0;
    }

    if (_state.msg_send_wq) {
        flush_workqueue(_state.msg_send_wq);
        destroy_workqueue(_state.msg_send_wq);
        _state.msg_send_wq = NULL;
    }

    num_rec_queued = atomic_read(&_state.num_rec_queued);
    if (num_rec_queued != 0) {
        amp_log_err("num_rec_queued (%d) != 0", num_rec_queued);
    }

    if (_state.is_nl_reg) {
        /* unregister generic netlink family */
        err = GENL_UNREGISTER_FAMILY_WITH_OPS(&_g_genl_family, _g_genl_ops);
        if (err != 0) {
            amp_log_err("GENL_UNREGISTER_FAMILY_WITH_OPS failed (%d)", err);
        }
        _state.is_nl_reg = 0;
    }

    if (_state.path_kmem_cache) {
        kmem_cache_destroy(_state.path_kmem_cache);
        _state.path_kmem_cache = NULL;
    }

    if (_state.fileop_data_kmem_cache) {
        kmem_cache_destroy(_state.fileop_data_kmem_cache);
        _state.fileop_data_kmem_cache = NULL;
    }

    mutex_destroy(&_state.portid_mutex);

    amp_log_info("stopping ampfsm");
}
