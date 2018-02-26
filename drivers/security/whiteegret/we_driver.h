/*
 * WhiteEgret Linux Security Module
 *
 * Copyright (C) 2017 Toshiba Corporation
 */

#ifndef _WE_DRIVER_H
#define _WE_DRIVER_H

#ifndef WE_LKM
#include <sys/types.h>
#endif

#define WE_DEV_NAME "wecom"
#define WE_DEV_PATH "/dev/"WE_DEV_NAME

#define SHORTNAMELENGTH 256

struct we_req_user {
	pid_t pid;
	pid_t ppid;
	char shortname[SHORTNAMELENGTH];
	int pathsize;
	char path[0];
};

struct we_ack {
	int permit;
	pid_t ppid;
};

#endif  /* _WE_DRIVER_H */
