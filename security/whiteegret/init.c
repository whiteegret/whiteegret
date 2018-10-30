// SPDX-License-Identifier: GPL-2.0
/*
 * WhiteEgret Linux Security Module
 *
 * Copyright (C) 2017-2018 Toshiba Corporation
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation, version 2.
 */

#define pr_fmt(fmt) "WhiteEgret: " fmt

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/security.h>
#include "we.h"

#include <linux/lsm_hooks.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("WhiteEgret Linux Security Module");

static int we_security_bprm_check(struct linux_binprm *bprm)
{
	if (!bprm)
		return 0;

	if (we_security_bprm_check_main(bprm) == -EACCES)
		return -EACCES;

	return 0;
}

static int we_security_mmap_check(struct file *file, unsigned long reqprot,
		unsigned long prot, unsigned long flags)
{
	if (!file)
		return 0;

	if (we_security_mmap_check_main(file, reqprot, flags) == -EACCES)
		return -EACCES;

	return 0;
}

#if defined(CONFIG_SECURITY_WHITEEGRET_HOOK_FILE_READ) || \
	defined(CONFIG_SECURITY_WHITEEGRET_HOOK_FILE_WRITE)
static int we_security_access_check(struct file *file, int mask)
{
	if (!file)
		return 0;
	return we_security_access_check_main(file, mask);
}
#endif

#if defined(CONFIG_SECURITY_WHITEEGRET_HOOK_READ_OPEN) || \
	defined(CONFIG_SECURITY_WHITEEGRET_HOOK_WRITE_OPEN)
static int we_security_open_check(struct file *file)
{
	if (!file)
		return 0;
	return we_security_open_check_main(file);
}
#endif

#ifdef CONFIG_SECURITY_WHITEEGRET_HOOK_WRITE
static int we_security_rename_check(struct path *old_dir,
				    struct dentry *old_dentry,
				    struct path *new_dir,
				    struct dentry *new_dentry)
{
	struct path new_path;

	if (!new_dir)
		return 0;

	new_path.mnt = new_dir->mnt;
	new_path.dentry = new_dentry;
	return we_security_rename_check_main(&new_path);
}
#endif

#ifdef CONFIG_SECURITY_WHITEEGRET_CHECK_LIVING_TASK
static int we_task_alloc_check(struct task_struct *task,
			       unsigned long clone_flag)
{
	if (!task)
		return 0;

	return we_security_task_alloc_check_main(task, clone_flag);
}

static void we_task_free_check(struct task_struct *task)
{
	if (!task)
		return;

	we_security_task_free_check_main(task);
}
#endif

static struct security_hook_list we_hooks[] = {
	LSM_HOOK_INIT(bprm_check_security, we_security_bprm_check),
	LSM_HOOK_INIT(mmap_file, we_security_mmap_check),
#if defined(CONFIG_SECURITY_WHITEEGRET_HOOK_READ_OPEN) || \
	defined(CONFIG_SECURITY_WHITEEGRET_HOOK_WRITE_OPEN)
	LSM_HOOK_INIT(file_open, we_security_open_check),
#endif
#ifdef CONFIG_SECURITY_WHITEEGRET_HOOK_WRITE
	LSM_HOOK_INIT(path_rename, we_security_rename_check),
#endif
#if defined(CONFIG_SECURITY_WHITEEGRET_HOOK_FILE_READ) || \
	defined(CONFIG_SECURITY_WHITEEGRET_HOOK_FILE_WRITE)
	LSM_HOOK_INIT(file_permission, we_security_access_check),
#endif
#ifdef CONFIG_SECURITY_WHITEEGRET_CHECK_LIVING_TASK
	LSM_HOOK_INIT(task_alloc, we_task_alloc_check),
	LSM_HOOK_INIT(task_free, we_task_free_check),
#endif
};

static int __init we_init(void)
{
	int rc;

	security_add_hooks(we_hooks, ARRAY_SIZE(we_hooks), "whiteegret");

	rc = we_specific_init();
	if (rc) {
		pr_err("error %d at %d in %s\n", rc, __LINE__, __FILE__);
		return rc;
	}

	pr_warn("WhiteEgret (LSM) initialized.\n");

	return 0;
}

static void __exit we_exit(void)
{
	we_specific_exit();

	pr_warn("WhiteEgret (LSM) exited.\n");
}

module_init(we_init);
module_exit(we_exit);
