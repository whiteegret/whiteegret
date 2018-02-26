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

#include <linux/binfmts.h>

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
	unsigned long ino;                /* inode number */
	unsigned int dmajor;              /* major version of device number */
	unsigned int dminor;              /* minor version of device number */
	char shortname[SHORTNAMELENGTH];  /* short name for the object */
	int pathsize;
	char *path;                       /* full path to the object */
	pid_t pid;
	pid_t ppid;
};

int we_security_bprm_check_main(struct linux_binprm *bprm);
int we_security_mmap_check_main(struct file *file,
		unsigned long reqprot, unsigned long flags);

int we_specific_init(void);
int we_specific_exit(void);

#endif  /* _WE_H */
