/*
 * WhiteEgret Linux Security Module
 *
 * Copyright (C) 2017-2018 Toshiba Corporation
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation, version 2.
 */

#ifndef _WE_FS_COMMON_H
#define _WE_FS_COMMON_H

#define WE_FS_DIR_NAME "whiteegret"
#define WE_DEV_NAME "wecom"
#define WE_DEV_PATH "/sys/kernel/security/"WE_FS_DIR_NAME"/"WE_DEV_NAME

#define SHORTNAMELENGTH 256

struct we_req_user {
	unsigned long ino;
	unsigned int dmajor;
	unsigned int dminor;
	pid_t pid;
	pid_t ppid;
	char shortname[SHORTNAMELENGTH];
	int pathsize;
	char path[0];
};

struct we_ack {
	int permit;
	pid_t pid;
};

#endif  /* _WE_FS_COMMON_H */
