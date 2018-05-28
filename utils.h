/**
 * @brief Helper Utilities
 *        Copyright 2016-2018 Cisco Systems
 *        GNU Public License
 */
#ifndef UTILS_H
#define UTILS_H

#include <linux/types.h>
#include <stddef.h>

/**
 * @brief Normalize a Linux file path. This does not follow symlinks.
 *
 * @details This method removes all occurrences of `/../` and `/./` from a given
 *          file path.
 *
 *          Example:
 *
 *          Input: /home/user/Downloads/../../root/Documents/doc.xml
 *          Output: /home/root/Documents/doc.xml
 *
 * @param[out] dst - Buffer to store normalized path
 * @param[in] dst_size - Maximum size of dst buffer
 * @param[in] src - Path to normalize
 * @param[in] src_len - Length of src path
 *
 * @return Length of the normalized path (as given in dst) or -1 on error
 */
int path_normalize(char *dst, size_t dst_size,
                   const char *src, size_t src_len);

#endif
