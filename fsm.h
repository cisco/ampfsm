/**
 * @brief Filesystem Module
 *        Copyright 2016-2018 Cisco Systems
 *        GNU Public License
 */
#ifndef FSM_H
#define FSM_H

#include "include/comm.h"

/* Buffer to store a path string; uses small buffer optimization.
 * The small buffer size is set to a value that keep the structure
 * compact (i.e., much smaller than one page) but still have give
 * decent chance for the optimization to be valuable. The current
 * setting intends to keep the size of fileop_path_buffer_t
 * to less than 256 bytes.*/
#define FILEOP_PATH_SMALL_BUF_SIZE (128)
typedef struct fileop_path_buffer {
    union {
        char small_buf[FILEOP_PATH_SMALL_BUF_SIZE];
        char *large_buf;
    } storage;

    /* Size of allocated buffer:
     *   If greater-than-zero, storage was allocated and large_buf is in use.
     *   If zero, storage was not allocatedd and small_buf is in use. */
    size_t capacity;
} fileop_path_buffer_t;

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
    fileop_path_buffer_t path_buffer;
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
 * @brief Free fileop_data_t struct. Does not touch data->pwd.
 *
 * @param[in] data - fileop_data_t struct to free
 */
void fileop_free(fileop_data_t *data);

/**
 * @brief While running in the context of a process, populate data->pwd, which
 *        is used to generate a path prefix.
 *        If the path attr of the given fileop_data_t structure is an absolute
 *        path, set pwd to the fs root.
 *        Otherwise, if the dirfd attr of the given fileop_data_t structure is
 *        AT_FDWCD, set pwd to the current pwd.
 *        Otherwise, set pwd to the path of the dirfd attr.
 *        This function assumes data, data->path and data->dirfd are valid.
 * @note If this function returns success, data->pwd will be set and it is the
 *       responsibilty of the caller to later free it with path_put(). Note that
 *       path_put() may not be called when preemption is disabled (e.g. in a
 *       kprobe handler)
 *
 * @param[in] data - Pointer to file operation structure
 *
 * @return 0 on success, -1 on error
 */
int fileop_set_pwd(fileop_data_t *data);

#endif
