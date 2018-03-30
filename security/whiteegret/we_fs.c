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
#include <linux/kernel.h>
#include <linux/security.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/cdev.h>

#include "we_fs.h"

#define static_assert(constexpr) \
	char dummy[(constexpr) ? 1 : -1] __attribute__((unused))

#define WE_COPY_TO_USER(to, from, ret) \
	do { \
		static_assert(sizeof((to)) == sizeof((from))); \
		(ret) = copy_to_user(&(to), &(from), sizeof(to)); \
	} while (0)

#define WE_COPY_FROM_USER(to, from, ret) \
	do { \
		static_assert(sizeof((to)) == sizeof((from))); \
		(ret) = copy_from_user(&(to), &(from), sizeof(to)); \
	} while (0)

static struct we_req_q_head *root;
struct task_struct *from_task;
static DEFINE_RWLOCK(from_task_lock);

static int check_we_pathsize(struct we_req_q *we_req, int size)
{
	if (size - sizeof(*we_req)
			> we_req->data.we_obj_info->pathsize)
		return 0;
	else
		return -1;
}

static int set_we_req_info(struct we_req_user *user,
		struct we_obj_info *info)
{
	unsigned long ret;

	WE_COPY_TO_USER(user->ino, info->ino, ret);
	if (ret != 0)
		return -EFAULT;
	WE_COPY_TO_USER(user->dmajor, info->dmajor, ret);
	if (ret != 0)
		return -EFAULT;
	WE_COPY_TO_USER(user->dminor, info->dminor, ret);
	if (ret != 0)
		return -EFAULT;
	WE_COPY_TO_USER(user->pid, info->pid, ret);
	if (ret != 0)
		return -EFAULT;
	WE_COPY_TO_USER(user->ppid, info->ppid, ret);
	if (ret != 0)
		return -EFAULT;
	WE_COPY_TO_USER(user->shortname, info->shortname, ret);
	if (ret != 0)
		return -EFAULT;
	WE_COPY_TO_USER(user->pathsize, info->pathsize, ret);
	if (ret != 0)
		return -EFAULT;
	if (info->pathsize) {
		ret = copy_to_user(user->path, info->path, info->pathsize + 1);
		if (ret != 0)
			return -EFAULT;
	}

	return 0;
}

static int set_we_ack(struct we_ack *to, struct we_ack *from)
{
	unsigned long ret;

	WE_COPY_FROM_USER(to->pid, from->pid, ret);
	if (ret != 0)
		return -EFAULT;
	WE_COPY_FROM_USER(to->permit, from->permit, ret);
	if (ret != 0)
		return -EFAULT;

	return 0;
}

static struct we_req_user *get_alive_we_req(struct we_req_q_head *root,
		void *buf, int size)
{
	int pathsize;
	struct list_head *p;
	struct we_req_q *req;
	struct we_req_user *user = NULL;

	write_lock(&root->lock);
	list_for_each(p, &root->head) {
		req = list_entry(p, struct we_req_q, queue);
		if (req->finish_flag == STOP_EXEC) {
			if (unlikely(check_we_pathsize(req, size)))
				goto SIZE_ERROR;
			user = (struct we_req_user *)buf;
			set_we_req_info(user, req->data.we_obj_info);
			break;
		}
	}
	write_unlock(&root->lock);

	return user;
SIZE_ERROR:
	pathsize = req->data.we_obj_info->pathsize;
	req->permit = -EACCES;
	req->finish_flag = START_EXEC;
	write_unlock(&root->lock);
	pr_err("Path length of exec is too long (%d).\n", pathsize);
	return NULL;
}

static ssize_t send_ack(struct we_req_q_head *root, struct we_ack *ack)
{
	struct list_head *p;
	struct we_req_q *req = NULL, *temp;

	write_lock(&root->lock);
	list_for_each(p, &root->head) {
		temp = list_entry(p, struct we_req_q, queue);
		if ((temp->data.we_obj_info->pid == ack->pid)
				&& (temp->finish_flag != START_EXEC)) {
			req = temp;
			req->permit = ack->permit;
			req->finish_flag = START_EXEC;
			wake_up_interruptible_sync(&req->waitq);
			break;
		}
	}
	write_unlock(&root->lock);

	if (unlikely(!req)) {
		pr_warn("%s: can not find we_req. pid(%d)\n",
			__func__, ack->pid);
		return -EACCES;
	}
	return sizeof(*ack);
}

static ssize_t we_driver_read(struct file *file, char *buf,
		size_t size, loff_t *off)
{
	int ret;
	struct we_req_user *user;

	while (1) {
		ret = wait_event_interruptible(root->waitq,
				(user = get_alive_we_req(root, buf, size)));
		if (unlikely(ret < 0)) {
			pr_info("%s: signal (%d)", __func__, ret);
			return 0;
		}
		if (likely(user))
			break;
	}

	return 1;
}

static ssize_t we_driver_write(struct file *file, const char *buf,
		size_t size, loff_t *off)
{
	int rc;
	ssize_t ret;
	struct we_ack ack;

	rc = set_we_ack(&ack, (struct we_ack *)((void *)buf));
	if (rc < 0)
		return (ssize_t)rc;
	ret = send_ack(root, &ack);

	return ret;
}

static long we_driver_ioctl(struct file *file,
		unsigned int arg0, unsigned long arg1)
{
	return 0;
}

static int we_driver_release(struct inode *inode, struct file *filp)
{
	int ret = 0;

	write_lock(&from_task_lock);
	if (!from_task) {
		pr_warn("WhiteEgret has not started.\n");
		ret =  -EACCES;
		goto END;
	}
	if (from_task != current) {
		pr_warn("This task is not registered to WhiteEgret.\n");
		ret = -EACCES;
		goto END;
	}
	from_task = NULL;
	we_req_q_cleanup();
END:
	write_unlock(&from_task_lock);
	return ret;
}

static int we_driver_open(struct inode *inode, struct file *filp)
{
	write_lock(&from_task_lock);
	if (from_task) {
		write_unlock(&(from_task_lock));
		pr_warn("WhiteEgret has already started.\n");
		return -EACCES;
	}

	from_task = current;
	root = &we_q_head;
	write_unlock(&from_task_lock);

	return 0;
}

static const struct file_operations we_driver_fops = {
	.owner = THIS_MODULE,
	.read = we_driver_read,
	.write = we_driver_write,
	.unlocked_ioctl = we_driver_ioctl,
	.open =  we_driver_open,
	.release = we_driver_release,
};

int we_fs_init(void)
{
	struct dentry *we_dir;
	struct dentry *wecom;

	we_dir = securityfs_create_dir(WE_FS_DIR_NAME, NULL);
	if (IS_ERR(we_dir))
		return PTR_ERR(we_dir);

	wecom = securityfs_create_file(WE_DEV_NAME, 0600, we_dir, NULL, &we_driver_fops);
	if (IS_ERR(wecom)) {
		securityfs_remove(we_dir);
		return PTR_ERR(wecom);
	}

	return 0;
}

/**
 * send_we_obj_info - Wait response from user's whitelisting application.
 *
 * @req: Pointer to struct we_req_q.
 *
 * Returns 0 if succeeded, < 0 otherwise.
 */
int send_we_obj_info(struct we_req_q *req)
{
	/* If there exists queue waiting for this request req done,
	 * then wake it up.
	 */
	if (waitqueue_active(&(we_q_head.waitq)))
		wake_up(&(we_q_head.waitq));

	return wait_event_interruptible_timeout(req->waitq,
			(req->finish_flag == START_EXEC),
			WERESULTTIMEOUT);
}
