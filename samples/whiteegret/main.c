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
	fprintf(stderr, "Usage: sample-we-user [file_name]\n");
	fprintf(stderr, "file_name: absolute path of executable");
	fprintf(stderr, "not to permit execution.\n");
}

int main(int argc, char *argv[])
{
	int fd;
	struct we_req_user *user;
	struct we_ack ack;
	char buf[1024];
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

		ack.pid = user->pid;
		check_whitelist(&ack.permit, user);

		ret = write(fd, (char *)&ack, sizeof(ack));
	}

	close(fd);

	return 0;
}
