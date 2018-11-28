/**
 * @brief Filesystem Module
 *        Copyright 2016-2018 Cisco Systems
 *        GNU Public License
 */
#ifndef FSM_H
#define FSM_H

#include "include/comm.h"

/* File operation information */
typedef struct {
    /* Kernel */
    struct work_struct work;
    int dirfd;
    struct path pwd;
    /* User space */
    amp_fsm_op_t op;
    char *path;
    pid_t pid;
    pid_t ppid;
    uid_t uid;
} fileop_data_t;

/**
 * @brief Create a new filesystem operation object.
 *
 * @param[in] op - File operation type
 * @param[in] dirfd - File descriptor of directory where filename got moved to.
 *                    This will be set only when filename is relative.
 * @param[in] filename - Filename buffer in the user address space
 *
 * @return Pointer to newly allocated fileop_data_t struct or NULL on error.
 */
fileop_data_t *fileop_new(amp_fsm_op_t op, int dirfd, const char __user *filename);

/**
 * @brief Free fileop_data_t struct.
 *
 * @param[in] data - fileop_data_t struct to free
 */
void fileop_free(fileop_data_t *data);

/**
 * @brief While running in the context of a process, check if the path attr
 *        of the given fileop_data_t structure is an absolute path. If so, do
 *        nothing. If not, generate an absolute path based on the current
 *        relative path and the dirfd.
 *
 * @param[in] data - Pointer to file operation structure
 *
 * @return 0 on success, -1 on error
 */
int fileop_set_path(fileop_data_t *data);

#endif
