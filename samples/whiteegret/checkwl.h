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

int check_whitelist(int *result, struct we_req_user *user);

#endif
