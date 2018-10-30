/* SPDX-License-Identifier: GPL-2.0 */
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

/* Control nothing*/
#define CONTROL_NONE	0x00
/* Control execution of executables */
#define CONTROL_EXEC	0x01
/* Control read of files */
#define CONTROL_READ	0x02
/* Check exit task */
#define CONTROL_EXIT	0x04
/* Check open for write */
#define CONTROL_WRITE	0x08
/* Check clone task */
#define CONTROL_FORK	0x10

/* permit LSM function */
#define WE_EXEC_OK	0

/* ioctl request number */
/* ask the kernel if it has more than one request */
#define WE_IOCTL_CHECK_HAS_REQUEST 1000

struct target_info {
	unsigned long ino; /* inode number */
	unsigned int dmajor; /* major version of device number */
	unsigned int dminor; /* minor version of device number */
	int pathsize;
	char path[0];
};

struct we_req_user {
	int cmd;
	pid_t pid;
	pid_t ppid;
	pid_t tgid;
	struct target_info info;
};

struct we_ack {
	int permit;
	pid_t tgid;
};

#endif  /* _WE_FS_COMMON_H */
