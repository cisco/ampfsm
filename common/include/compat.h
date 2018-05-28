/**
 @brief AMP Device Flow Control
        Linux kernel API compatibility layer
        Copyright 2015-2018 Cisco Systems
        GNU Public License
 @author Craig Davison <crdaviso@cisco.com>
 @date 2015 Feb 10
*/

/* defines to aid with supporting multiple Linux kernel versions */

#ifndef AMP_NKE_COMPAT_H
#define AMP_NKE_COMPAT_H

#include <linux/inet.h>
#include <linux/version.h>
#include <net/genetlink.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
#   define HAVE_SCHED_MM_H
#   define HAVE_SCHED_TASK_H
#endif

/* task_uid() */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0)
#   define TASK_UID(task) \
        __kuid_val(task_uid(task))
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
#   define TASK_UID(task) \
        task_uid(task)
#else
#   define TASK_UID(task) \
        ((task)->uid)
#endif

/* struct msghdr */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0)
#   define STRUCT_MSGHDR_HAS_IOCB
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,19,0)
#   define STRUCT_MSGHDR_HAS_IOV_ITER
#endif

/* struct proto.accept */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
#   define PROTO_ACCEPT_HAS_KERN
#endif

/* get current uptime as a u64. use div_u64 if available as this is more
 * efficient on 32-bit archs */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
#   define CUR_UPTIME() \
        (div_u64(get_jiffies_64(), HZ))
#else
#   define CUR_UPTIME() \
        (get_jiffies_64() / HZ)
#endif

/* INET6_ADDRSTRLEN */
#ifndef INET6_ADDRSTRLEN
#   define INET6_ADDRSTRLEN (48)
#endif

/* dentry_path_raw */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,38)
#   define HAVE_DENTRY_PATH_RAW
#endif

/* reinit_completion */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,13,0)
#   define REINIT_COMPLETION(completion) \
        reinit_completion(completion)
#else
#   define REINIT_COMPLETION(completion) \
        INIT_COMPLETION(*(completion))
#endif

/* mm_struct has exe_file */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
#   define MM_STRUCT_EXE_FILE
#endif

/* struct file has f_path */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
#   define STRUCT_FILE_F_PATH
#endif

/* kmem_cache_create */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,23)
#   define KMEM_CACHE_CREATE(name, size, align, flags, ctor) \
        kmem_cache_create(name, size, align, flags, ctor)
#else
#   define KMEM_CACHE_CREATE(name, size, align, flags, ctor) \
        kmem_cache_create(name, size, align, flags, ctor, NULL)
#endif

/* two-parameter INIT_WORK */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
#   define INIT_WORK_USES_CONTAINER
#endif

/* netlink portid */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0)
#   define NETLINK_USES_PORTID
#endif

/* genlmsg_unicast */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32)
#   define GENLMSG_UNICAST(net, skb, portid) \
        genlmsg_unicast(net, skb, portid)
#else
#   define GENLMSG_UNICAST(net, skb, portid) \
        genlmsg_unicast(skb, portid)
#endif

/* RHEL macros */
#ifndef RHEL_RELEASE_VERSION
#   define RHEL_RELEASE_VERSION(a,b) (((a) << 8) + (b))
#endif
#ifndef RHEL_RELEASE_CODE
#   define RHEL_RELEASE_CODE RHEL_RELEASE_VERSION(0,0)
#endif

/* genl_register_family_with_ops
 *
 * Kernel 4.10+, and RHEL 7.5 (kernel 3.10.0-862): not present - use only genl_register_family
 * Kernel 3.13+, and RHEL 7.1 - 7.4 (kernel 3.10.0-229 - 3.10.0-693): 2-arg version
 * Kernel 2.6.31+ (but not RHEL 7.1 - 7.5): 3-arg version
 * Older kernels: not present - use genl_register_family and genl_register_ops
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0) || RHEL_RELEASE_CODE == RHEL_RELEASE_VERSION(7,5)
static inline int __amp_genl_register_family_with_ops(struct genl_family *family,
                                                      struct genl_ops *ops,
                                                      int n_ops)
{
    family->module = THIS_MODULE;
    family->ops = ops;
    family->n_ops = n_ops;
    family->mcgrps = NULL;
    family->n_mcgrps = 0;
    return genl_register_family(family);
}
#   define GENL_REGISTER_FAMILY_WITH_OPS(family, ops) \
        __amp_genl_register_family_with_ops(family, ops, ARRAY_SIZE(ops))
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,13,0) || (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,1) && RHEL_RELEASE_CODE <= RHEL_RELEASE_VERSION(7,4))
#   define GENL_REGISTER_FAMILY_WITH_OPS(family, ops) \
        genl_register_family_with_ops(family, ops)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31)
#   define GENL_REGISTER_FAMILY_WITH_OPS(family, ops) \
        genl_register_family_with_ops(family, ops, ARRAY_SIZE(ops))
#else
static inline int __amp_genl_register_family_with_ops(struct genl_family *family,
                                                      struct genl_ops *ops,
                                                      int n_ops)
{
    int ret = 0;
    int err;
    int i;
    int last_registered_ops = -1;
    err = genl_register_family(family);
    if (err != 0) {
        ret = err;
        goto done;
    }
    for (i = 0; i < n_ops; i++) {
        err = genl_register_ops(family, &ops[i]);
        if (err != 0) {
            ret = err;
            goto unreg;
        }
        last_registered_ops = i;
    }
    /* success */
    goto done;
unreg:
    for (i = last_registered_ops; i >= 0; i--) {
        (void)genl_unregister_ops(family, &ops[i]);
    }
    (void)genl_unregister_family(family);
done:
    return ret;
}
#   define GENL_REGISTER_FAMILY_WITH_OPS(family, ops) \
        __amp_genl_register_family_with_ops(family, ops, ARRAY_SIZE(ops))
#endif

/* genl_unregister_family - with ops
 *
 * Kernel 3.13+, and RHEL 7.1 - 7.5 (kernel 3.10.0-229 - 3.10.0-862): use only genl_unregister_family
 * Older kernels (but not RHEL 7.1 - 7.5): use genl_unregister_family and genl_unregister_ops
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,13,0) || (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,1) && RHEL_RELEASE_CODE <= RHEL_RELEASE_VERSION(7,5))
#   define GENL_UNREGISTER_FAMILY_WITH_OPS(family, ops) \
        genl_unregister_family(family)
#else
static inline int __amp_genl_unregister_family_with_ops(struct genl_family *family,
                                                        struct genl_ops *ops,
                                                        int n_ops)
{
    int ret = 0;
    int err;
    int i;
    for (i = n_ops-1; i >= 0; i--) {
        err = genl_unregister_ops(family, &ops[i]);
        if (err != 0) {
            ret = err;
            goto done;
        }
    }
    err = genl_unregister_family(family);
    if (err != 0) {
        ret = err;
        goto done;
    }
done:
    return ret;
}
#   define GENL_UNREGISTER_FAMILY_WITH_OPS(family, ops) \
        __amp_genl_unregister_family_with_ops(family, ops, ARRAY_SIZE(ops))
#endif

/* genlmsg_put */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
#   define GENLMSG_PUT(skb, portid, seq, family, flags, cmd) \
        genlmsg_put(skb, portid, seq, family, flags, cmd)
#else
#   define GENLMSG_PUT(skb, portid, seq, family, flags, cmd) \
        genlmsg_put(skb, portid, seq, (family)->id, (family)->hdrsize, flags, cmd, (family)->version)
#endif

#endif

