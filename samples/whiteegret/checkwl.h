/*
 * WhiteEgret Linux Security Module
 *
 * Sample program of user's whitelisting application
 *
 * Copyright (C) 2017 Toshiba Corporation
 */

#ifndef _CHECKWL_H
#define _CHECKWL_H

#ifdef CONFIG_SECURITY_WHITEEGRET_DRIVER
#include "we_driver.h"
#else
#include <linux/netlink.h>
#endif

/* byte length of absolute path of file not to permit execution */
#define NOTPERMITEXENAMELENGTH 1024

extern char not_permit_exe[NOTPERMITEXENAMELENGTH];

#ifdef CONFIG_SECURITY_WHITEEGRET_DRIVER
int check_whitelist(int *result, struct we_req_user *user);
#else
int check_whitelist(int *result, struct nlattr *attrs[]);
#endif

#endif
