/**
 * @brief AMP Filesystem Module Communication API
 *        Copyright 2016-2018 Cisco Systems
 */
#ifndef AMP_FSM_COMM_H
#define AMP_FSM_COMM_H

/* generic netlink - version number for our protocol */
#define AMP_FSM_GENL_VERSION 1

/* generic netlink - unique family name
   max GENL_NAMSIZ (16) bytes */
#define AMP_FSM_GENL_FAM_NAME "csco-amp-fsm"

/* file operation flags - bitmask */
typedef uint32_t amp_fsm_op_t;
#define AMP_FSM_OP_RENAME (0x00000001)
#define AMP_FSM_OP_ALL    (0xffffffff)

/* generic netlink - commands */
enum {
    AMP_FSM_CMD_UNSPEC,
    AMP_FSM_CMD_HELLO,     /* Initial message sent by user-space program
                              to kernel */
    AMP_FSM_CMD_SET_OPTS,  /* Set options */
    AMP_FSM_CMD_REC_OP,    /* Kernel file operation event */
    AMP_FSM_CMD_REC_HELLO, /* Kernels response to userland hello message */
};

/* generic netlink - attributes */
enum {
    AMP_FSM_ATTR_UNSPEC,
    /* options */
    AMP_FSM_ATTR_LOG_LEVEL,     /* Log level */
    AMP_FSM_ATTR_FILEOP_FILTER, /* File operation filter */
    /* file operation event data */
    AMP_FSM_ATTR_REC_OP,        /* File operation */
    AMP_FSM_ATTR_REC_PID,       /* Process ID */
    AMP_FSM_ATTR_REC_PPID,      /* Parent Process ID */
    AMP_FSM_ATTR_REC_UID,       /* User ID */
    AMP_FSM_ATTR_REC_PATH,      /* File path */
    /* last entry: */
    AMP_FSM_ATTR_COUNT
};

#endif
