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

#include <errno.h>
#include <string.h>
#include "checkwl.h"

/*
 * The function check_whitelist() returns -EACCES
 * only when path to be examined equals to @a not_permit_exe.
 */
char not_permit_exe[NOTPERMITEXENAMELENGTH];

/**
 * check_whitelist - Examine whether the executable input to this function
 *                   is included in whitelist or not.
 *
 * @result: Result of the examination.
 *            0       if the executble is included in whitelist
 *            -EACCES otherwise ("not included")
 *
 * Returns 0 for success, -1 otherwise.
 */
int check_whitelist(int *result, struct we_req_user *user)
{
	char *path;

	if (result == NULL)
		return -1;

	*result = 0;

	if (user == NULL)
		return -1;

	path = user->path;

	/*
	 * Referring a whitelist is expected at this location.
	 * However, this sample uses not whitelist but blacklist
	 * because of avoiding a host to become uncontrollable.
	 * (not_permit_exe is a blacklist containing only one item.)
	 */
	if (strncmp(not_permit_exe, path, NOTPERMITEXENAMELENGTH) == 0)
		*result = -EACCES;

	return 0;
}
