/**
 * @brief File Operation Module Test Client
 *        Copyright 2016-2018 Cisco Systems
 *        GNU Public License
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <unistd.h>
#include <fcntl.h>
#include <libmnl/libmnl.h>
#include <linux/genetlink.h>
#include <syslog.h>
#include <string.h>

#include "../include/comm.h"

#define DUMP_CMD_FREQ 5
#define CMDLINE_OPTS "f:l:h"
#define RECV_SOCKET_BUFFER_SIZE \
    ((getpagesize() << 2) < 16384L ? (getpagesize() << 2) : 16384L)

struct cb_data {
    uint16_t amp_family_id;
    bool is_set;
    bool hello_rec;
    struct mnl_socket *nl;
    unsigned int *seq;
};

static struct nlmsghdr *_prepare_msg(char *buf, uint16_t type, uint16_t flags,
                                     uint32_t seq, uint8_t version, uint8_t cmd)
{
    struct genlmsghdr *genl;
    struct nlmsghdr *nlh;
    nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = type;
    nlh->nlmsg_flags = flags;
    nlh->nlmsg_seq = seq;
    genl = mnl_nlmsg_put_extra_header(nlh, sizeof(struct genlmsghdr));
    genl->cmd = cmd;
    genl->version = version;
    return nlh;
}

static int _genl_ctrl_attr_cb(const struct nlattr *attr, void *data)
{
    const struct nlattr **tb = data;
    uint16_t type;
    int ret = MNL_CB_OK;

    if (mnl_attr_type_valid(attr, CTRL_ATTR_MAX) < 0) {
        perror("mnl_attr_type_valid");
        ret = MNL_CB_ERROR;
        goto done;
    }

    type = mnl_attr_get_type(attr);
    switch(type) {
        case CTRL_ATTR_FAMILY_NAME:
            if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0) {
                perror("mnl_attr_validate");
                ret = MNL_CB_ERROR;
                goto done;
            }
            break;
        case CTRL_ATTR_FAMILY_ID:
            if (mnl_attr_validate(attr, MNL_TYPE_U16) < 0) {
                perror("mnl_attr_validate");
                ret = MNL_CB_ERROR;
                goto done;
            }
            break;
        default:
            break;
    }
    tb[type] = attr;

done:
    return ret;
}

static int _rec_attr_cb(const struct nlattr *attr, void *data)
{
    const struct nlattr **tb = data;
    uint16_t type;
    int ret = MNL_CB_OK;

    if (mnl_attr_type_valid(attr, AMP_FSM_ATTR_COUNT-1) < 0) {
        perror("mnl_attr_type_valid");
        ret = MNL_CB_ERROR;
        goto done;
    }

    type = mnl_attr_get_type(attr);
    switch (type) {
        case AMP_FSM_ATTR_REC_OP:
        case AMP_FSM_ATTR_REC_PID:
        case AMP_FSM_ATTR_REC_PPID:
        case AMP_FSM_ATTR_REC_UID:
            if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
                fprintf(stderr, "mnl_attr_validate: %d\n", type);
                ret = MNL_CB_ERROR;
                goto done;
            }
            break;
        case AMP_FSM_ATTR_REC_PATH:
            if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0) {
                perror("mnl_attr_validate");
                ret = MNL_CB_ERROR;
                goto done;
            }
            break;
        default:
            break;
    }
    tb[type] = attr;

done:
    return ret;
}

static int _data_cb(const struct nlmsghdr *nlh, void *data)
{
    struct genlmsghdr *genl = mnl_nlmsg_get_payload(nlh);
    struct cb_data *cb_data = data;
    int err;
    int ret = MNL_CB_OK;

    if (nlh->nlmsg_type == cb_data->amp_family_id) {
        struct nlattr *tb[AMP_FSM_ATTR_COUNT] = {};
        err = mnl_attr_parse(nlh, sizeof(*genl), _rec_attr_cb, tb);
        if (err != MNL_CB_OK) {
            ret = err;
            goto done;
        }

        switch(genl->cmd) {
            case AMP_FSM_CMD_REC_OP:
                printf("EVENT");
                break;
            case AMP_FSM_CMD_REC_HELLO:
                printf("HELLO REC");
                cb_data->hello_rec = true;
                break;
            default:
                printf("???");
                break;
        }

        if (tb[AMP_FSM_ATTR_REC_OP]) {
            switch (mnl_attr_get_u8(tb[AMP_FSM_ATTR_REC_OP])) {
                case AMP_FSM_OP_RENAME:
                    printf(" RENAME");
                    break;
                default:
                    printf(" ???");
                    break;
            }
        }
        if (tb[AMP_FSM_ATTR_REC_PID]) {
            printf(" pid %d", mnl_attr_get_u32(tb[AMP_FSM_ATTR_REC_PID]));
        }
        if (tb[AMP_FSM_ATTR_REC_PPID]) {
            printf(" ppid %d", mnl_attr_get_u32(tb[AMP_FSM_ATTR_REC_PPID]));
        }
        if (tb[AMP_FSM_ATTR_REC_UID]) {
            printf(" uid %d", mnl_attr_get_u32(tb[AMP_FSM_ATTR_REC_UID]));
        }
        if (tb[AMP_FSM_ATTR_REC_PATH]) {
            printf(" path %s", mnl_attr_get_str(tb[AMP_FSM_ATTR_REC_PATH]));
        }
        printf("\n");
    } else if (nlh->nlmsg_type == GENL_ID_CTRL) {
        struct nlattr *tb[CTRL_ATTR_MAX+1] = {};
        printf("genl ctrl msg\n");
        err = mnl_attr_parse(nlh, sizeof(*genl), _genl_ctrl_attr_cb, tb);
        if (err != MNL_CB_OK) {
            ret = err;
            goto done;
        }
        if (tb[CTRL_ATTR_FAMILY_ID]) {
            cb_data->amp_family_id = mnl_attr_get_u16(tb[CTRL_ATTR_FAMILY_ID]);
            cb_data->is_set = true;
        }
    }
done:
    return ret;
}

static int _rec_msg(struct cb_data *cb_data, char *buf, int buf_size, struct mnl_socket *nl, unsigned int seq, unsigned int portid)
{
    int n;
    int run = 1;
    int ret = -1;

    while (run > 0) {
        n = mnl_socket_recvfrom(nl, buf, buf_size);
        if (n <= 0) {
            if (n < 0) {
                perror("mnl_socket_recvfrom");
            } else {
                fprintf(stderr, "mnl_socket_recvfrom: disconnected\n");
            }
            goto done;
        }
        run = mnl_cb_run(buf, n, seq, portid, _data_cb, cb_data);
        if (run < 0) {
            if (errno == ENOENT) {
                fprintf(stderr, "Can not find family %s - kernel module may "
                                "not be loaded\n", AMP_FSM_GENL_FAM_NAME);
            }
            perror("mnl_cb_run");
            goto done;
        }
    }
    ret = 0;
done:
    return ret;
}

static void _usage(const char *name)
{
    printf("\nUSAGE: %s [OPTIONS]\n\n"
           "\t-f\tFile operation filter (rename)\n"
           "\t-l\tLog level (emerg, alert, crit, err,\n"
           "\t\twarning, notice, info, debug)\n\n", name);
}

int main(int argc, char **argv)
{
    struct mnl_socket *nl = NULL;
    char buf[RECV_SOCKET_BUFFER_SIZE];
    struct nlmsghdr *nlh;
    int ret = EXIT_FAILURE;
    unsigned int seq, portid;
    struct cb_data cb_data = { 0, false, false, NULL, 0 };
    int n;
    char c;
    int run;
    int fd;
    fd_set rfds;
    int flags;
    int err;
    struct timeval timeout;
    bool reconnect;

    uint32_t opt_fileop_filter = 0;
    uint8_t opt_log_level = LOG_DEBUG;

    /* parse cmdline */
    while ((c = getopt(argc, argv, CMDLINE_OPTS)) != -1) {
        switch (c) {
            case 'f':
                if (strcmp(optarg, "rename") == 0) {
                    opt_fileop_filter |= AMP_FSM_OP_RENAME;
                } else {
                    fprintf(stderr, "Invalid filter: %s\n", optarg);
                    _usage(argv[0]);
                    goto done;
                }
                break;
            case 'l':
                if (strcmp(optarg, "emerg") == 0) {
                    opt_log_level = LOG_EMERG;
                } else if (strcmp(optarg, "alert") == 0) {
                    opt_log_level = LOG_ALERT;
                } else if (strcmp(optarg, "crit") == 0) {
                   opt_log_level = LOG_CRIT;
                } else if (strcmp(optarg, "err") == 0) {
                   opt_log_level = LOG_ERR;
                } else if (strcmp(optarg, "warning") == 0) {
                   opt_log_level = LOG_WARNING;
                } else if (strcmp(optarg, "notice") == 0) {
                   opt_log_level = LOG_NOTICE;
                } else if (strcmp(optarg, "info") == 0) {
                   opt_log_level = LOG_INFO;
                } else if (strcmp(optarg, "debug") == 0) {
                   opt_log_level = LOG_DEBUG;
                } else {
                    fprintf(stderr, "Invalid log level: %s\n", optarg);
                    _usage(argv[0]);
                    goto done;
                }
                break;
            case 'h':
            default:
                _usage(argv[0]);
                goto done;
        }
    }

    /* connect to generic netlink */
    nl = mnl_socket_open(NETLINK_GENERIC);
    if (nl == NULL) {
        perror("mnl_socket_open");
        goto done;
    }

    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
        perror("mnl_socket_bind");
        goto done;
    }

    portid = mnl_socket_get_portid(nl);
    cb_data.nl = nl;
    cb_data.seq = &seq;

    /* get the family ID for AMP_NKE_GENL_FAM_NAME */
    seq = (time(NULL) & 0x00ffffff) << 8;
    nlh = _prepare_msg(buf, GENL_ID_CTRL, NLM_F_REQUEST | NLM_F_ACK, seq,
                       1 /* version */, CTRL_CMD_GETFAMILY);
    mnl_attr_put_u32(nlh, CTRL_ATTR_FAMILY_ID, GENL_ID_CTRL);
    mnl_attr_put_strz(nlh, CTRL_ATTR_FAMILY_NAME, AMP_FSM_GENL_FAM_NAME);

    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        perror("mnl_socket_sendto");
        goto done;
    }

    if(_rec_msg(&cb_data, buf, sizeof(buf), nl, seq, portid) != 0) {
        goto done;
    }

    if (!cb_data.is_set) {
        fprintf(stderr, "No response from genl_ctrl\n");
        goto done;
    }

    printf("Family ID: %" PRIu16 "\n", cb_data.amp_family_id);

    do {
        reconnect = false;

        if (!nl) {
            /* connect to generic netlink */
            nl = mnl_socket_open(NETLINK_GENERIC);
            if (nl == NULL) {
                perror("mnl_socket_open");
                goto done;
            }
            if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
                perror("mnl_socket_bind");
                goto done;
            }
            portid = mnl_socket_get_portid(nl);
        }

        /* send hello */
        printf("Sending Hello...\n");
        seq++;
        nlh = _prepare_msg(buf, cb_data.amp_family_id, NLM_F_REQUEST | NLM_F_ACK, seq,
                           AMP_FSM_GENL_VERSION, AMP_FSM_CMD_HELLO);
            if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
            perror("mnl_socket_sendto");
            goto done;
        }

        /* Recieve hello rec */
        printf("Looking for AMP_FSM_CMD_HELLO_REC response...\n");
        if(_rec_msg(&cb_data, buf, sizeof(buf), nl, seq, portid) != 0) {
            goto done;
        }

        if (!cb_data.hello_rec) {
            fprintf(stderr, "No AMP_FSM_CMD_HELLO_REC response from kernel module\n");
            goto done;
        }
        printf("AMP_FSM_CMD_HELLO_REC response recieved from kernel module\n");

        /* set options */
        seq++;
        nlh = _prepare_msg(buf, cb_data.amp_family_id, NLM_F_REQUEST, seq,
                           AMP_FSM_GENL_VERSION, AMP_FSM_CMD_SET_OPTS);
        mnl_attr_put_u8(nlh, AMP_FSM_ATTR_LOG_LEVEL, opt_log_level);
        mnl_attr_put_u32(nlh, AMP_FSM_ATTR_FILEOP_FILTER, opt_fileop_filter);

        if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
            perror("mnl_socket_sendto");
            goto done;
        }

        /* put socket in non-blocking mode */
        fd = mnl_socket_get_fd(nl);
        flags = fcntl(fd, F_GETFL, 0);
        if (flags == -1) {
            perror("fcntl(F_GETFL)");
            goto done;
        }

        err = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        if (err != 0) {
            perror("fcntl(F_SETFL)");
            goto done;
        }

        /* start receiving events */
        do {
            timeout.tv_sec = 1;
            timeout.tv_usec = 0;
            FD_ZERO(&rfds);
            FD_SET(fd, &rfds);

            n = select(fd+1, &rfds, NULL, NULL, &timeout);
            if (n < 0) {
                perror("select");
                goto done;
            }

            if (n > 0) {
                n = mnl_socket_recvfrom(nl, buf, sizeof(buf));
                while (n > 0) {
                    run = mnl_cb_run(buf, n, 0 /* seq */, portid,
                                     _data_cb, &cb_data);
                    if (run < 0) {
                        if (errno == EPERM) {
                            fprintf(stderr, "Operation requires CAP_NET_ADMIN "
                                    "(run as root)\n");
                        }
                        perror("mnl_cb_run");
                        goto done;
                    }
                    n = mnl_socket_recvfrom(nl, buf, sizeof(buf));
                }
                if (n < 0 && errno != EAGAIN) {
                    perror("mnl_socket_recvfrom");
                    if (errno != ENOBUFS) {
                        goto done;
                    }
                }
                if (n == 0) {
                    fprintf(stderr, "mnl_socket_recvfrom: disconnected\n");
                    reconnect = true;
                    break;
                }
            }
        } while (1);

        if (reconnect) {
            mnl_socket_close(nl);
            nl = NULL;
            usleep(10000);
        }
    } while (reconnect);

    ret = EXIT_SUCCESS;
done:
    if (nl) {
        mnl_socket_close(nl);
        nl = NULL;
    }

    return ret;
}

