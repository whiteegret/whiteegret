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

#ifndef _WE_H
#define _WE_H

#include "we_fs_common.h"

/*
 * Initial size in byte of memory allocation to store the path
 * of an object file
 */
#define EXPECTPATHSIZE 1023

/*
 * Default size in byte to expand block that stores the path
 * of an object file when the memory block is too small
 * to store the path
 */
#define ADDEDEXPECTPATHSIZE 1023

/* Maximum length in byte of path of object file */
#define MAXPATHSIZE 8184

/* Maximum length in byte of name of executable file */
#define SHORTNAMELENGTH 256

/*
 * Maximum number of retry for sending the same message
 * to user whitelisting application
 */
#define MAXCOMRETRY 10

/* Timeout value in millisecond to aquire the semaphore */
#define WERESULTTIMEOUT 1000

/*
 * Structure for an object to be tested whether it is contained
 * in the whitelist or not
 */
struct we_obj_info {
	char *fpath_kernel;
	struct we_req_user req_user;
};

struct path;
struct linux_binprm;
struct file;
struct task_struct;

int we_security_bprm_check_main(struct linux_binprm *bprm);
int we_security_mmap_check_main(struct file *file,
				unsigned long reqprot, unsigned long flags);
int we_security_open_check_main(struct file *file);
int we_security_rename_check_main(struct path *new_path);
int we_security_access_check_main(struct file *file, int mask);
int we_security_task_alloc_check_main(struct task_struct *task,
				      unsigned long clone_flags);
void we_security_task_free_check_main(struct task_struct *task);

int we_specific_init(void);
int we_specific_exit(void);

#endif  /* _WE_H */
