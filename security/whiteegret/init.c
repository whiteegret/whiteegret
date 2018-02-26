/*
 * WhiteEgret Linux Security Module
 *
 * Copyright (C) 2017 Toshiba Corporation
 */

#include <linux/module.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/fs.h>
#include <linux/lsm_hooks.h>
#include "we.h"
#include "print_msg.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("WhiteEgret Linux Security Module");
MODULE_VERSION("1.0.0");

static int we_security_bprm_check(struct linux_binprm *bprm)
{
	if (we_security_bprm_check_main(bprm) == -EPERM)
		return -EPERM;

	return 0;
}

static int we_security_mmap_check(struct file *file, unsigned long reqprot,
		unsigned long prot, unsigned long flags)
{
	if (we_security_mmap_check_main(file, reqprot, flags) == -EPERM)
		return -EPERM;

	return 0;
}

static struct security_hook_list we_hooks[] = {
	LSM_HOOK_INIT(bprm_check_security, we_security_bprm_check),
	LSM_HOOK_INIT(mmap_file, we_security_mmap_check),
};

static int __init we_init(void)
{
	int rc;

	if (!security_module_enable("whiteegret"))
		return 0;

	security_add_hooks(we_hooks, ARRAY_SIZE(we_hooks), "whiteegret");

	rc = we_specific_init();
	if (rc) {
		PRINT_ERROR(rc);
		return rc;
	}

	PRINT_WARNING("WhiteEgret (LSM) initialized.\n");

	return 0;
}

static void __exit we_exit(void)
{
	we_specific_exit();

	PRINT_WARNING("WhiteEgret (LSM) exited.\n");
}

module_init(we_init);
module_exit(we_exit);
