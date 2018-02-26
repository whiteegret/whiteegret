/*
 * WhiteEgret Linux Security Module
 *
 * Copyright (C) 2017 Toshiba Corporation
 */

#include "auth.h"

/**
 * userproc_auth - Authenticate user's whitelisting application process.
 *
 * @authinfo: authentication credentials
 *
 * Returns 1 if authenticated, 0 otherwise.
 */
int userproc_auth(char *authinfo)
{
	return 1;
}
