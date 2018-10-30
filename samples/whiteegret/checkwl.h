/* SPDX-License-Identifier: GPL-2.0 */
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

#ifndef _CHECKWL_H
#define _CHECKWL_H

#include <sys/types.h>
#include "we_fs_common.h"

/* byte length of absolute path of file not to permit execution */
#define NOTPERMITEXENAMELENGTH 1024

extern char not_permit_exe[NOTPERMITEXENAMELENGTH];
extern char monitor_interpreter[NOTPERMITEXENAMELENGTH];
extern char not_permit_script[NOTPERMITEXENAMELENGTH];

void init_terp_proc(void);
int check_whitelist_exec(int *result, struct we_req_user *user);
int check_whitelist_terp(int *result, struct we_req_user *user);
int check_fork_terp(int *result, struct we_req_user *user);
int check_exit_terp(int *result, struct we_req_user *user);

#endif
