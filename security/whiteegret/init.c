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

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/fs.h>
#include "we.h"

#include <linux/lsm_hooks.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("WhiteEgret Linux Security Module");

static int we_security_bprm_check(struct linux_binprm *bprm)
{
	if (we_security_bprm_check_main(bprm) == -EACCES)
		return -EACCES;

	return 0;
}

static int we_security_mmap_check(struct file *file, unsigned long reqprot,
		unsigned long prot, unsigned long flags)
{
	if (we_security_mmap_check_main(file, reqprot, flags) == -EACCES)
		return -EACCES;

	return 0;
}

static struct security_hook_list we_hooks[] = {
	LSM_HOOK_INIT(bprm_check_security, we_security_bprm_check),
	LSM_HOOK_INIT(mmap_file, we_security_mmap_check),
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
