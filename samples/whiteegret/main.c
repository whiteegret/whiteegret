/*
 * WhiteEgret Linux Security Module
 *
 * Sample program of user's whitelisting application
 *
 * Copyright (C) 2017 Toshiba Corporation
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "checkwl.h"

#ifdef CONFIG_SECURITY_WHITEEGRET_DRIVER

#include <stdlib.h>
#include "we_driver.h"

#else

#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/mngt.h>
#include <netlink/cache-api.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include "gennl_common.h"
#include "gennl_user.h"

#endif

#define MAXWAITFROMKER 10

#ifndef CONFIG_SECURITY_WHITEEGRET_DRIVER
int kerfamilyid = -1;
int receiving_from_ker = 1;
#endif

static void sigint_catch(int sig)
{
#ifndef CONFIG_SECURITY_WHITEEGRET_DRIVER
	receiving_from_ker = 0;
#endif
}

static void print_usage(void)
{
	fprintf(stderr, "Usage: sample-we-user [file_name]\n");
	fprintf(stderr, "file_name: absolute path of executable");
	fprintf(stderr, "not to permit execution.\n");
}

int main(int argc, char *argv[])
{
#ifdef CONFIG_SECURITY_WHITEEGRET_DRIVER
	int fd;
	struct we_req_user *user;
	struct we_ack ack;
	char buf[2024];
#else
	struct nl_handle *h;
	int sockfd;
	struct nl_cb *cb;
	struct recv_payload_st recvdata;
	int epfd;
	struct epoll_event ev, ev_ret[1];
	int j;
	int nfds;
#endif
	int ret;

	if (argc < 2) {
		print_usage();
		return -1;
	}

	snprintf(not_permit_exe, NOTPERMITEXENAMELENGTH, "%s", argv[1]);

	signal(SIGINT, sigint_catch);

	if (daemon(0, 0) < 0) {
		perror("daemon");
		exit(EXIT_FAILURE);
	}

#ifdef CONFIG_SECURITY_WHITEEGRET_DRIVER

	fd = open(WE_DEV_PATH, O_RDWR, 0);
	if (fd < 0) {
		perror(WE_DEV_PATH);
		exit(EXIT_FAILURE);
	}
	user = (struct we_req_user *)((void *)buf);

	while (1) {
		ret = read(fd, (char *)user, 256);
		if (ret < 0) {
			perror("read");
			continue;
		}

		ack.ppid = user->ppid;
		check_whitelist(&ack.permit, user);

		ret = write(fd, (char *)&ack, sizeof(ack));
	}

	close(fd);

#else  /* CONFIG_SECURITY_WHITEEGRET_DRIVER */

	/* initialize and connect for netlink handler */
	h = nl_handle_alloc();
	if (!h) {
		nl_perror("nl_handle_alloc");
		return -1;
	}

	if (genl_connect(h) < 0) {
		nl_perror("genl_connect");
		nl_close(h);
		return -1;
	}

	sockfd = nl_socket_get_fd(h);
	if (nl_socket_set_nonblocking(h) < 0) {
		nl_perror("nl_socket_set_nonblocking");
		nl_close(h);
		return -1;
	}

	cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (cb == NULL) {
		nl_perror("nl_cb_alloc");
		nl_close(h);
		return -1;
	}

	/* find the family ID for white list netlink in kernel */
	for (j = 0; j < MAXWAITFROMKER; j++) {
		kerfamilyid = genl_ctrl_resolve(h, WE_FAMILY_NAME);
		if ((kerfamilyid >= 0) || (!receiving_from_ker))
			break;
		nl_perror("genl_ctrl_resolve");
	}
	if ((j >= MAXWAITFROMKER) || (!receiving_from_ker)) {
		perror("error in opening kernel netlink.");
		nl_close(h);
		exit(EXIT_FAILURE);
	}

	/* register the user process as the user's whitelist application */
	if (send_we_user_register(kerfamilyid, h, NULL) < 0) {
		perror("fatal error at send_we_user_register.");
		nl_close(h);
		return -1;
	}

	/* disable sequence number check */
	if (nl_cb_set(cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM,
				seq_num_no_check_callback, NULL) < 0) {
		nl_perror("nl_cb_set");
		goto unregister;
	}

	/* set callback function for receiving generic netlink message */
	recvdata.familyid = kerfamilyid;
	recvdata.nlhandle = h;
	if (nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM,
				we_user_execpermission_callback,
				(void *)&recvdata) < 0) {
		nl_perror("nl_cb_set");
		goto unregister;
	}

	/* preparing polling */
	epfd = epoll_create(1);
	if (epfd < 0) {
		perror("epoll_create");
		goto unregister;
	}

	memset(&ev, 0, sizeof(ev));
	ev.events = EPOLLIN;
	ev.data.fd = sockfd;

	if (epoll_ctl(epfd, EPOLL_CTL_ADD, sockfd, &ev) != 0) {
		perror("epoll_ctl");
		goto unregister;
	}

	/* polling */
	while (receiving_from_ker) {
		nfds = epoll_wait(epfd, ev_ret, 1, -1);
		if (nfds < 0) {
			if (errno != EINTR) {
				perror("epoll_wait");
				goto unregister;
			}
		}
		for (j = 0; j < nfds; j++) {
			if (ev_ret[j].data.fd == sockfd) {
				ret = nl_recvmsgs(h, cb);
				if (ret < 0) {
					nl_perror("nl_recvmsgs");
					goto unregister;
				}
			}
		}
	}

unregister:
	/* unregister the user process */
	ret = send_we_user_unregister(kerfamilyid, h, NULL);
	if (ret < 0) {
		perror("fatal error at send_we_user_unregister.");
		nl_close(h);
		return -1;
	}

	nl_close(h);

#endif  /* CONFIG_SECURITY_WHITEEGRET_DRIVER */

	return 0;
}

