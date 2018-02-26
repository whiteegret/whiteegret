/*
 * WhiteEgret Linux Security Module
 *
 * Sample program of user's whitelisting application
 *
 * Copyright (C) 2017 Toshiba Corporation
 */

#include <errno.h>
#include <string.h>
#include "checkwl.h"

#ifndef CONFIG_SECURITY_WHITEEGRET_DRIVER
#include "gennl_common.h"
#include "gennl_user.h"
#endif

/*
 * The function check_whitelist() returns -EPERM
 * only when path to be examined equals to @a not_permit_exe.
 */
char not_permit_exe[NOTPERMITEXENAMELENGTH];

/**
 * check_whitelist - Examine whether the executable input to this function
 *                   is included in whitelist or not.
 *
 * @result: Result of the examination.
 *            0      if the executble is included in whitelist
 *            -EPERM otherwise ("not included")
 *
 * Returns 0 for success, -1 otherwise.
 */
#ifdef CONFIG_SECURITY_WHITEEGRET_DRIVER
int check_whitelist(int *result, struct we_req_user *user)
#else
int check_whitelist(int *result, struct nlattr *attrs[])
#endif
{
	char *path;
#ifndef CONFIG_SECURITY_WHITEEGRET_DRIVER
	int path_byte_len;
	int margin = 2;  /* margin size for terminating null byte */
#endif

	*result = 0;

#ifdef CONFIG_SECURITY_WHITEEGRET_DRIVER
	if ((result == NULL) || (user == NULL))
#else
	if ((result == NULL) || (attrs == NULL))
#endif
		return -1;

#ifdef CONFIG_SECURITY_WHITEEGRET_DRIVER
	path = user->path;
#else
	path_byte_len = strlen(nla_get_string(attrs[WE_A_PATH]));
	path = (char *)calloc(path_byte_len + margin, sizeof(char));
	if (path == NULL)
		return -1;
	snprintf(path, path_byte_len + margin, "%s",
			nla_get_string(attrs[WE_A_PATH]));
#endif

	/*
	 * Refering a whitelist is expected at this location.
	 * However, this sample uses not whitelist but blacklist
	 * because of avoiding a host to become uncontrollable.
	 * (not_permit_exe is a blacklist containing only one item.)
	 */
	if (strcmp(not_permit_exe, path) == 0)
		*result = -EPERM;

#ifndef CONFIG_SECURITY_WHITEEGRET_DRIVER
	free(path);
#endif

	return 0;
}
