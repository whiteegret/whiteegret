// SPDX-License-Identifier: GPL-2.0
/*
 * WhiteEgret Linux Security Module
 *
 * Sample program of user's whitelisting application
 *
 * Copyright (C) 2017-2018 Toshiba Corporation
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation, version 2.
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

#include <stdlib.h>
#include "we_fs_common.h"

#define MAXWAITFROMKER 10

static void sigint_catch(int sig)
{
}

static void print_usage(void)
{
	fprintf(stderr, "Usage: sample-we-user <executable file name> ");
	fprintf(stderr,	"<interpreter file name> <script file name>\n");
	fprintf(stderr, "executable file name: absolute path of executable ");
	fprintf(stderr,	"not to permit execution.\n");
	fprintf(stderr, "interpreter file name: absolute path of");
	fprintf(stderr, "interpreter monitoring script read.\n");
	fprintf(stderr, "script file name: absolute path of script file");
	fprintf(stderr, "not to permit reading(execution).\n");
	fprintf(stderr, "If you want to use controling script file, ");
	fprintf(stderr, "you enable WhiteEgret Kernel option ");
	fprintf(stderr, "CONFIG_SECURITY_WHITEEGRET_INTERPRETER.\n");
}

static int check_whitelist(int *result, struct we_req_user *user)
{
	int ret;

	switch (user->cmd) {
	case CONTROL_EXEC:
		ret = check_whitelist_exec(result, user);
		break;
	case CONTROL_READ:
		ret = check_whitelist_terp(result, user);
		break;
	case CONTROL_FORK:
		ret = check_fork_terp(result, user);
		break;
	case CONTROL_EXIT:
		ret = check_exit_terp(result, user);
		break;
	}
	return ret;
}

int main(int argc, char *argv[])
{
	int fd;
	struct we_req_user *user;
	struct we_ack ack;
	char buf[1024];
	int ret;

	if (argc < 4) {
		print_usage();
		return -1;
	}

	init_terp_proc();
	snprintf(not_permit_exe, NOTPERMITEXENAMELENGTH, "%s", argv[1]);
	snprintf(monitor_interpreter, NOTPERMITEXENAMELENGTH, "%s", argv[2]);
	snprintf(not_permit_script, NOTPERMITEXENAMELENGTH, "%s", argv[3]);

	signal(SIGINT, sigint_catch);

	if (daemon(0, 0) < 0) {
		perror("daemon");
		exit(EXIT_FAILURE);
	}

	fd = open(WE_DEV_PATH, O_RDWR, 0);
	if (fd < 0) {
		perror(WE_DEV_PATH);
		exit(EXIT_FAILURE);
	}
	user = (struct we_req_user *)((void *)buf);

	while (1) {
		ret = read(fd, (char *)user, 1024);
		if (ret < 0) {
			perror("read");
			continue;
		}

		ack.tgid = user->tgid;
		check_whitelist(&ack.permit, user);

		ret = write(fd, (char *)&ack, sizeof(ack));
	}

	close(fd);

	return 0;
}
