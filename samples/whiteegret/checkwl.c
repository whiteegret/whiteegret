// SPDX-License-Identifier: GPL-2.0
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
#include <stdlib.h>
#include "checkwl.h"

/*
 * The function check_whitelist_exec() set -EACCES to result
 * only when path to be examined equals to @a not_permit_exe.
 */
char not_permit_exe[NOTPERMITEXENAMELENGTH];

/*
 * The function check_whitelist_exec() store monitoring interpreter
 * only when path to be examined equals to @a monitor_interpreter.
 */
char monitor_interpreter[NOTPERMITEXENAMELENGTH];

/*
 * The function check_whitelist_terp() set -EACCES to result
 * only when path to be examined equals to @a not_permit_script.
 */
char not_permit_script[NOTPERMITEXENAMELENGTH];

/*
 * The struct records interpreter process tgid.
 * This tgid recorded in @a root_terp_proc.
 */
struct terp_proc {
	struct terp_proc *next;
	pid_t tgid;
};
static struct terp_proc *root_terp_proc;

void init_terp_proc(void)
{
	root_terp_proc = NULL;
}

static void register_terp_proc(pid_t tgid)
{
	struct terp_proc *proc;

	proc = calloc(1, sizeof(*proc));
	if (!proc)
		return;

	proc->tgid = tgid;
	proc->next = root_terp_proc;
	root_terp_proc = proc;
}

static void unregister_terp_proc(pid_t tgid)
{
	struct terp_proc *now, *back;

	if (!root_terp_proc)
		return;

	if (root_terp_proc->tgid == tgid) {
		root_terp_proc = root_terp_proc->next;
		return;
	}
	for (back = root_terp_proc, now = back->next; now != NULL;
	     back = now, now = now->next) {
		if (now->tgid == tgid) {
			back->next = now->next;
			free(now);
			break;
		}
	}
}

static struct terp_proc *get_terp_proc(pid_t tgid)
{
	struct terp_proc *now;

	for (now = root_terp_proc; now != NULL; now = now->next) {
		if (now->tgid == tgid)
			return now;
	}
	return NULL;
}

/**
 * check_whitelist_exec - Examine whether the executable input to this function
 *			  is included in whitelist or not.
 *
 * @result: Result of the examination.
 *	    0       if the executble is included in whitelist
 *	    -EACCES otherwise ("not included")
 *
 * Returns 0 for success, -1 otherwise.
 */
int check_whitelist_exec(int *result, struct we_req_user *user)
{
	char *path;

	if (result == NULL)
		return -1;

	*result = WE_EXEC_OK;

	if (user == NULL)
		return -1;

	path = user->info.path;

	/*
	 * Referring a whitelist is expected at this location.
	 * However, this sample uses not whitelist but blacklist
	 * because of avoiding a host to become uncontrollable.
	 * (not_permit_exe is a blacklist containing only one item.)
	 */
	if (strncmp(not_permit_exe, path, NOTPERMITEXENAMELENGTH) == 0)
		*result = -EACCES;
	/*
	 * Referring a list is monitered a interpreter at this location.
	 * This location registers a tgid of monitering interpreter.
	 * Monitering interpreter is limited reading script.
	 */
	else if (strncmp(monitor_interpreter, path,
			 NOTPERMITEXENAMELENGTH) == 0)
		register_terp_proc(user->tgid);
	return 0;
}

/**
 * check_whitelist_terp - Examine whether the script input to this function
 *			  is included in whitelist or not, if the process
 *			  input to this function is registered in
 *			  @root_terp_proc.
 *
 * @result: Result of the examination.
 *	    0       if the script is included in whitelist,
 *		    or not registered process
 *	    -EACCES otherwise ("not included")
 *
 * Returns 0 for success, -1 otherwise.
 */
int check_whitelist_terp(int *result, struct we_req_user *user)
{
	if (result == NULL)
		return -1;

	*result = WE_EXEC_OK;

	/*
	 * if process reading a file is registered, referring a whitelist
	 * is expected at this location.
	 * However, this sample uses not whitelist but blacklist
	 * because of avoiding a host to become uncontrollable.
	 * (not_permit_script is a blacklist containing only one item.)
	 */
	if (get_terp_proc(user->tgid)) {
		if (strncmp(not_permit_script, user->info.path,
			    NOTPERMITEXENAMELENGTH) == 0)
			*result = -EACCES;
	}
	return 0;
}

/**
 * check_fork_terp - Register the child process to @root_terp_proc,
 *		     if the parent process already has registerd to
 *		     @root_terp_proc.
 *
 * Returns Allways 0.
 */
int check_fork_terp(int *result, struct we_req_user *user)
{
	if (result == NULL)
		return -1;

	*result = WE_EXEC_OK;
	/*
	 * A child process of a interpreter has possibilities interpreter.
	 * This location registers a tgid of child process case of
	 * interpreter.
	 */
	if (get_terp_proc(user->ppid))
		register_terp_proc(user->tgid);
	return 0;
}

/**
 * check_exit_terp - Unregister the process form @root_terp_proc,
 *		     case of matching @root_terp_proc.
 *
 * @result: Allways 0.
 */
int check_exit_terp(int *result, struct we_req_user *user)
{
	if (result == NULL)
		return -1;

	*result = WE_EXEC_OK;
	/*
	 * This location unregisters exit process with interpreter.
	 */
	unregister_terp_proc(user->tgid);
	return 0;
}
