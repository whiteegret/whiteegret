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

#include <linux/binfmts.h>
#include <linux/fs.h>
#include <linux/mman.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include "we.h"
#include "request.h"
#include "we_fs.h"

#include <linux/sched/signal.h>

#ifdef CONFIG_SECURITY_WHITEEGRET_CHECK_LIVING_TASK
/*
 * This structure is registered exit process then task_free.
 */
struct we_obj_info_stack {
	struct we_obj_info_stack *next;
	struct we_obj_info we_obj_info;
};
static struct we_obj_info_stack *root_we_obj_info;
static DEFINE_RWLOCK(root_we_obj_info_lock);
#endif

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

#ifdef CONFIG_SECURITY_WHITEEGRET_CHECK_LIVING_TASK
	root_we_obj_info = NULL;
#endif

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

static inline void set_we_obj_from_task_info(struct we_obj_info *we_obj_info,
					     struct task_struct *tsk)
{
	we_obj_info->req_user.pid = tsk->pid;
	we_obj_info->req_user.tgid = tsk->tgid;
	we_obj_info->req_user.ppid = task_ppid_nr(tsk);
}

static inline void set_we_obj_from_path_info(struct we_obj_info *we_obj_info,
					     struct inode *inode,
					     char *pathname)
{
	we_obj_info->fpath_kernel = pathname;
	we_obj_info->req_user.info.ino = inode->i_ino;
	we_obj_info->req_user.info.dmajor = MAJOR(inode->i_sb->s_dev);
	we_obj_info->req_user.info.dminor = MINOR(inode->i_sb->s_dev);
	we_obj_info->req_user.info.pathsize = strlen(pathname);
}

static int we_get_path(struct path *path,
		       char **ret_pathname, char **ret_pathnamebuf)
{
	char *pathname = NULL, *pathnamebuf = NULL;
	int pathsize = PAGE_SIZE;
	int rc = 0;

	if (!path || !path->dentry)
		goto failure;

	pathnamebuf = kmalloc(pathsize, GFP_KERNEL);
	if (unlikely(!pathnamebuf)) {
		rc = -ENOMEM;
		pr_err("error %d at %d in %s\n", rc, __LINE__, __FILE__);
		goto failure;
	}
	if (path->dentry->d_op && path->dentry->d_op->d_dname)
		pathname = path->dentry->d_op->d_dname
			(path->dentry, pathnamebuf, pathsize - 1);
	else
		pathname = d_absolute_path(path, pathnamebuf,
					   pathsize - 1);
	if (IS_ERR(pathname)) {
		rc = -ENOMEM;
		pr_err("error %d and %ld at %d in %s\n",
		       rc, PTR_ERR(pathname), __LINE__, __FILE__);
		goto failure;
	}
 failure:
	*ret_pathname = pathname;
	*ret_pathnamebuf = pathnamebuf;
	return rc;
}

/**
 * we_check_main - Common function for security_bprm_check and mmap_file.
 *
 * @file: Pointer to struct file.
 * @cmd: command infomation.
 *
 * Returns 0 if succeeded, < 0 otherwise.
 */
int we_check_main(struct path *path, int cmd)
{
	struct inode *inode;
	struct we_obj_info we_obj_info;
	char *pathnamebuf = NULL;
	char *pathname;
	int rc = 0;
	int checkresult;

	if (unlikely(!path) || unlikely(!path->dentry) ||
	    unlikely(!path->dentry->d_inode))
		goto failure;

	rc = we_get_path(path, &pathname, &pathnamebuf);
	if (rc != 0)
		goto failure;

	inode = path->dentry->d_inode;
	set_we_obj_from_path_info(&we_obj_info, inode, pathname);
	set_we_obj_from_task_info(&we_obj_info, current);
	we_obj_info.req_user.cmd = cmd;

	rc = send_receive_we_obj_info(&we_obj_info, &checkresult);
	if (rc < 0)
		goto failure;

	rc = checkresult;

	if (rc == -EACCES)
		pr_warn("block %s, ino=%ld, devno=0x%x.\n",
			pathname, we_obj_info.req_user.info.ino,
			MKDEV(we_obj_info.req_user.info.dmajor,
			      we_obj_info.req_user.info.dminor));
	else
		pr_info("permit %s, ino=%ld, devno=0x%x.\n",
			pathname, we_obj_info.req_user.info.ino,
			MKDEV(we_obj_info.req_user.info.dmajor,
			      we_obj_info.req_user.info.dminor));

failure:
	kfree(pathnamebuf);
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
static int send_receive_we_obj_info(struct we_obj_info *we_obj_info,
				    int *checkresult)
{
	int i;
	int rc;
	struct we_req_q req;
	int is_signal;

	we_req_q_init(&req, we_obj_info);

	rc = we_req_q_push(&req);
	if (rc < 0) {
		pr_err("error %d at %d in %s\n", rc,
		       __LINE__, __FILE__);
		goto failure;
	}

	is_signal = 0;
	for (i = 0; i < MAXCOMRETRY; i++) {
		rc = send_we_obj_info(&req);

		if (signal_pending(current)) {
			is_signal = 1;
			clear_tsk_thread_flag(current, TIF_SIGPENDING);
		}

		if (likely(req.finish_flag == START_EXEC))
			break;
	}

	we_req_q_pop(&req);

	if (is_signal)
		set_tsk_thread_flag(current, TIF_SIGPENDING);

	if (unlikely(i >= MAXCOMRETRY) && req.finish_flag != START_EXEC) {
		pr_err("error %d at %d in %s\n", rc, __LINE__, __FILE__);
		rc = -EINVAL;
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
	if (unlikely(!from_task) || unlikely(!bprm->file))
		return 0;

	return we_check_main(&bprm->file->f_path, CONTROL_EXEC);
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
	int ret = 0;

	if (unlikely(!from_task))
		return 0;

	if ((flags & MAP_EXECUTABLE))
		return 0;

	if (reqprot & PROT_EXEC) {
		ret = we_check_main(&file->f_path, CONTROL_EXEC);
		if (ret != 0)
			goto END;
	}

 END:
	return ret;
}

#if defined(CONFIG_SECURITY_WHITEEGRET_HOOK_READ_OPEN) || \
	defined(CONFIG_SECURITY_WHITEEGRET_HOOK_WRITE_OPEN)
/**
 * we_security_open_check_main - Target for open_file.
 *
 * @file: Pointer to struct file to open.
 *
 * Returns 0 if succeeded, < 0 otherwise.
 */
int we_security_open_check_main(struct file *file)
{
	int ret = 0;

	if (unlikely(!from_task) || from_task == current)
		goto END;

#ifdef CONFIG_SECURITY_WHITEEGRET_HOOK_READ_OPEN
	if (!(file->f_flags & O_WRONLY)) {
		ret = we_check_main(&file->f_path, CONTROL_READ);
		if (ret != 0)
			goto END;
	}
#endif

#ifdef CONFIG_SECURITY_WHITEEGRET_HOOK_WRITE_OPEN
	if (file->f_flags & (O_ACCMODE))
		ret = we_check_main(&file->f_path, CONTROL_WRITE);
#endif

 END:
	return ret;
}
#endif

#ifdef CONFIG_SECURITY_WHITEEGRET_HOOK_WRITE
/**
 * we_security_rename_check_main - Target for path_rename.
 *
 * @new_path: Pointer to struct path of destination file.
 *
 * Returns 0 if succeeded, < 0 otherwise.
 */
int we_security_rename_check_main(struct path *new_path)
{
	int ret = 0;

	if (unlikely(!from_task))
		goto END;
	if (unlikely(!new_path->dentry))
		goto END;
	/*
	 * Notifying information is rename destination file,
	 * not include information of rename source file.
	 */
	ret = we_check_main(new_path, CONTROL_WRITE);
 END:
	return ret;
}
#endif

#if defined(CONFIG_SECURITY_WHITEEGRET_HOOK_FILE_READ) || \
	defined(CONFIG_SECURITY_WHITEEGRET_HOOK_FILE_WRITE)
/**
 * we_security_access_check_main - Target for file_permission.
 *
 * @file: Pointer to struct file to access.
 * @mask: Access infomation.
 *
 * Returns 0 if succeeded, < 0 otherwise.
 */
int we_security_access_check_main(struct file *file, int mask)
{
	int ret = 0;

	if (unlikely(!from_task) || from_task == current)
		goto END;

#ifdef CONFIG_SECURITY_WHITEEGRET_HOOK_FILE_READ
	if (mask & MAY_READ) {
		ret = we_check_main(&file->f_path, CONTROL_READ);
		if (ret != 0)
			goto END;
	}
#endif

#ifdef CONFIG_SECURITY_WHITEEGRET_HOOK_FILE_WIRTE
	if (mask & MAY_WRITE)
		ret = we_check_main(&file->f_path, CONTROL_WRITE);
#endif

 END:
	return ret;
}
#endif

#ifdef CONFIG_SECURITY_WHITEEGRET_CHECK_LIVING_TASK
/**
 * we_security_task_alloc_check_main - Target for task_alloc.
 *
 * @task: Pointer to struct task creating now.
 * @clone_flags: infomation of creating task.
 *
 * Returns 0 if succeeded, < 0 otherwise.
 */
int we_security_task_alloc_check_main(struct task_struct *task,
				      unsigned long clone_flags)
{
	int checkresult = 0, rc = 0;
	struct we_obj_info_stack *node;

	if (unlikely(!from_task))
		return 0;

	/*
	 * This location notifies exiting task to
	 * the WhiteEgret User Application.
	 */
	while (1) {
		write_lock(&root_we_obj_info_lock);
		if (root_we_obj_info) {
			node = root_we_obj_info;
			root_we_obj_info = root_we_obj_info->next;
			write_unlock(&root_we_obj_info_lock);
			if (likely(from_task))
				rc = send_receive_we_obj_info
					(&node->we_obj_info, &checkresult);
			kfree(node);
		} else {
			write_unlock(&root_we_obj_info_lock);
			break;
		}
	}

	/*
	 * This location notify fork to the WhiteEgret User Application.
	 * Notifying infomation is exit process infomation, not include
	 * file information.
	 */
	if (!(clone_flags & CLONE_THREAD)) {
		struct we_obj_info info = {};

		set_we_obj_from_task_info(&info, current);
		info.req_user.cmd = CONTROL_FORK;
		rc = send_receive_we_obj_info(&info, &checkresult);
	}
	return 0;
}

/**
 * we_security_task_free_check_main - Target for task_free.
 *
 * @task: Pointer to struct task destroying now.
 *
 * Returns 0 if succeeded, < 0 otherwise.
 */
void we_security_task_free_check_main(struct task_struct *task)
{
	struct we_obj_info_stack *node;

	if (unlikely(!from_task) || from_task == task)
		return;

	if (get_nr_threads(task) > 1)
		return;

	node = kzalloc(sizeof(*node), GFP_ATOMIC);
	if (!node)
		return;

	set_we_obj_from_task_info(&node->we_obj_info, task);
	node->we_obj_info.req_user.cmd = CONTROL_EXIT;

	/*
	 * This location records exiting task.
	 * The kernel prints warning when communicating to
	 * the WhiteEgret User Application, threfore
	 * we_security_task_alloc_check_main() notify exiting task to
	 * the WhiteEgret User Application before notification of crating task.
	 * Notifying infomation is exit process infomation, not include
	 * file information.
	 */
	write_lock(&root_we_obj_info_lock);
	node->next = root_we_obj_info;
	root_we_obj_info = node;
	write_unlock(&root_we_obj_info_lock);
}
#endif
