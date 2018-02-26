/*
 * WhiteEgret Linux Security Module
 *
 * Copyright (C) 2017 Toshiba Corporation
 */

#ifndef _WE_H
#define _WE_H

#include <linux/binfmts.h>
#include <linux/version.h>
#include "we_common.h"

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

/*
 * Maximum number of retry for sending the same message
 * to user whitelisting application
 */
#define MAXCOMRETRY 3

/* Timeout value in millisecond to aquire the semaphore */
#define WERESULTTIMEOUT 1000

#ifndef CONFIG_SECURITY_WHITEEGRET_DRIVER

/*
 * Timeout value in jiffies to wait response from
 * user whitelisting application
 */
#define WEGENNLTIMEOUT 1000

#endif

/*
 * Structure for an object to be tested whether it is contained
 * in the whitelist or not
 */
struct we_obj_info {
	char shortname[SHORTNAMELENGTH];  /* short name for the object */
#ifdef CONFIG_SECURITY_WHITEEGRET_DRIVER
	int pathsize;
#endif
	char *path;                       /* full path to the object */
	pid_t pid;
#ifdef CONFIG_SECURITY_WHITEEGRET_DRIVER
	pid_t ppid;
#endif
};

int we_security_bprm_check_main(struct linux_binprm *bprm);
int we_security_mmap_check_main(struct file *file,
		unsigned long reqprot, unsigned long flags);

int we_specific_init(void);
int we_specific_exit(void);

#endif  /* _WE_H */
