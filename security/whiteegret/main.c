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
#include <linux/semaphore.h>
#include <linux/binfmts.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/mman.h>
#include "we.h"
#include "request.h"

#include <linux/sched.h>
#include <linux/module.h>
#include <linux/slab.h>
#include "we_fs.h"


static int send_receive_we_obj_info(
		struct we_obj_info *we_obj_info, int *checkresult);

/**
 * we_specific_init - Initialize fs.
 *
 * Returns 0.
 */
int we_specific_init(void)
{
	int rc = 0;

	rc = we_fs_init();
	if (rc < 0) {
		pr_err("error %d at %d in %s\n", rc, __LINE__, __FILE__);
		return rc;
	}

	we_req_q_head_init();

	return 0;
}

/**
 * we_specific_exit - Nothing to do in the implementation.
 *
 * Returns 0.
 */
int we_specific_exit(void)
{
	return 0;
}

/**
 * we_check_main - Common function for security_bprm_check and mmap_file.
 *
 * @file: Pointer to struct file.
 *
 * Returns 0 if succeeded, < 0 otherwise.
 */
int we_check_main(struct file *file)
{
	struct inode *inode;
	struct we_obj_info we_obj_info;
	char *pathnamebuf;
	char *new_pathnamebuf;
	char *pathname;
	char *shortnamebuf;
	int pathsize;
	int rc;
	int i;
	int checkresult;

	if (unlikely(file == NULL))
		return 0;

	pathsize = EXPECTPATHSIZE;
	pathnamebuf = kmalloc(pathsize, GFP_KERNEL);
	if (unlikely(!pathnamebuf)) {
		rc = -ENOMEM;
		pr_err("error %d at %d in %s\n", rc, __LINE__, __FILE__);
		goto failure;
	}
	while (pathsize <= MAXPATHSIZE) {
		pathname = d_absolute_path(&file->f_path, pathnamebuf,
				pathsize-1);
		if (!IS_ERR(pathname))
			break;

		pathsize += ADDEDEXPECTPATHSIZE;
		new_pathnamebuf = krealloc(pathnamebuf, pathsize,
				GFP_KERNEL);
		if (unlikely(!new_pathnamebuf)) {
			rc = -ENOMEM;
			pr_err("error %d at %d in %s\n", rc,
					__LINE__, __FILE__);
			goto failure;
		}
		pathnamebuf = new_pathnamebuf;
	}
	if (unlikely(pathsize >= MAXPATHSIZE)) {
		rc = -ENOMEM;
		pr_err("error %d at %d in %s\n", rc, __LINE__, __FILE__);
		goto failure;
	}

	shortnamebuf = pathname;
	for (i = 0; i < pathsize; i++) {
		if (pathname[i] == '\0')
			break;
		if (pathname[i] == '/')
			shortnamebuf = pathname + (i + 1);
	}
	strncpy(we_obj_info.shortname, shortnamebuf, SHORTNAMELENGTH);
	we_obj_info.path = pathname;
	inode = file_inode(file);
	we_obj_info.ino = inode->i_ino;
	we_obj_info.dmajor = MAJOR(inode->i_sb->s_dev);
	we_obj_info.dminor = MINOR(inode->i_sb->s_dev);
	we_obj_info.pid = current->pid;
	we_obj_info.pathsize = strlen(pathname);
	we_obj_info.ppid = current->tgid;

	rc = send_receive_we_obj_info(&we_obj_info, &checkresult);
	if (rc < 0)
		goto failure;

	rc = checkresult;

	if (rc == -EACCES)
		pr_warn("block %s, ino=%ld, devno=0x%x.\n",
			pathname, we_obj_info.ino,
			MKDEV(we_obj_info.dmajor, we_obj_info.dminor));
	else
		pr_info("permit %s, ino=%ld, devno=0x%x.\n",
			pathname, we_obj_info.ino,
			MKDEV(we_obj_info.dmajor, we_obj_info.dminor));

failure:
	if (pathnamebuf != NULL) {
		kfree(pathnamebuf);
		pathnamebuf = NULL;
	}

	if ((rc != 0) && (rc != -EACCES))
		pr_warn("Checking white list does not work.\n");

	return rc;
}

/**
 * send_receive_we_obj_info - Send message and wait.
 *
 * @we_obj_info: Pointer to struct we_obj_info.
 * @result: Pointer to result of matching to white list.
 *
 * Returns 0 if succeeded, < 0 otherwise.
 */
static int send_receive_we_obj_info(
		struct we_obj_info *we_obj_info, int *checkresult)
{
	int i;
	int rc;
	struct we_req_q req;

	we_req_q_init(&req, we_obj_info);

	if ((we_req_q_search(&(req.data))) == NULL) {
		rc = we_req_q_push(&req);
		if (rc < 0) {
			pr_err("error %d at %d in %s\n", rc,
					__LINE__, __FILE__);
			goto failure;
		}
	}

	for (i = 0; i < MAXCOMRETRY; i++) {
		rc = send_we_obj_info(&req);

		if (likely(req.finish_flag == START_EXEC)) {
			break;
		} else if (unlikely(rc == -ERESTARTSYS)) {
			pr_info("Signal detected (%d)\n", rc);
			break;
		}
	}

	we_req_q_pop(&req);

	if (unlikely(i >= MAXCOMRETRY) && req.finish_flag != START_EXEC) {
		rc = -EINVAL;
		pr_err("error %d at %d in %s\n", rc, __LINE__, __FILE__);
	}

	*checkresult = req.permit;

failure:
	return rc;
}

/**
 * we_security_bprm_check_main - Target for security_bprm_check.
 *
 * @bprm: Pointer to struct linux_binprm.
 *
 * Returns 0 if succeeded, < 0 otherwise.
 */
int we_security_bprm_check_main(struct linux_binprm *bprm)
{
	if (unlikely(!from_task))
		return 0;

	return we_check_main(bprm->file);
}

/**
 * we_security_mmap_check_main - Target for mmap_file.
 *
 * @file: Pointer to struct file to map.
 * @reqprot: Protection requested by the application.
 * @flags: Operational flags.
 *
 * Returns 0 if succeeded, < 0 otherwise.
 */
int we_security_mmap_check_main(struct file *file,
		unsigned long reqprot, unsigned long flags)
{
	if (unlikely(!from_task))
		return 0;

	if (!(reqprot & PROT_EXEC))
		return 0;

	if ((flags & MAP_EXECUTABLE))
		return 0;

	if (!file)
		return 0;

	if (!file->f_path.dentry)
		return 0;

	return we_check_main(file);
}
