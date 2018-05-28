/**
 * @brief Helper Utilities
 *        Copyright 2016-2018 Cisco Systems
 *        GNU Public License
 */

#include "utils.h"

#include <linux/string.h>

/**
 * @brief Reverse memchr().
 *
 * @param[in] s - Memory to search
 * @param[in] c - Byte to look for
 * @param[in] n - Size of memory buffer `s`
 *
 * @return Pointer to byte `c` in the memory buffer if found or NULL otherwise
 */
static void *_memrchr(const void *s, int c, size_t n)
{
    const char *ret = NULL;
    const char*  cp;

    if (n != 0) {
        cp = s + n;

       do {
           if (*(--cp) == (char) c) {
               ret = cp;
               break;
           }
       } while (--n != 0);
    }

    return (void*)ret;
}

int path_normalize(char *dst, size_t dst_size,
                   const char *src, size_t src_len)
{
    int dst_len = -1;
    const char *ptr = NULL;
    const char *end = NULL;
    const char *next = NULL;
    size_t next_len;
    const char *slash;

    if (!src || !dst || dst_size < src_len) {
        goto done;
    }

    ptr = src;
    end = &src[src_len];
    dst_len = 0;

    for (; ptr < end; ptr = next+1) {
        next = memchr(ptr, '/', end - ptr);
        if (!next) {
            next = end;
        }

        next_len = next - ptr;

        switch (next_len) {
            case 2:
                if (ptr[0] == '.' && ptr[1] == '.') {
                    slash = _memrchr(dst, '/', dst_len);
                    if (slash) {
                        dst_len = slash - dst;
                    }
                    continue;
                }
                break;
            case 1:
                if (ptr[0] == '.') {
                    continue;
                }
                break;
            case 0:
                continue;
            default:
                break;
        }
        dst[dst_len++] = '/';
        memcpy(&dst[dst_len], ptr, next_len);
        dst_len += next_len;
    }

    if (dst_len == 0) {
        dst[dst_len++] = '/';
    }
    dst[dst_len] = '\0';
done:
    return dst_len;
}
