/*
 * WhiteEgret Linux Security Module
 *
 * Copyright (C) 2017 Toshiba Corporation
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/cdev.h>
#include "dd_com.h"

/*
 * This option informs we_driver.h that this file is built as
 * loadable kernel module.
 */
#define WE_LKM
#include "we_driver.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Toshiba");

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

#define SUCCESS 0

#define WE_MINOR 1
#define WE_CLASS_NAME "we_class"

static int we_major;
static struct cdev we_cdev;
static struct class *we_class;

static rwlock_t resource_lock;
static struct we_req_q_head *root;

static struct we_req_q *get_alive_we_req(struct we_req_q_head *root)
{
	struct list_head *p;
	struct we_req_q *req, *ret = NULL;

	read_lock(&root->lock);
	list_for_each(p, &root->head) {
		req = list_entry(p, struct we_req_q, queue);
		if (req->finish_flag == STOP_EXEC) {
			ret = req;
			break;
		}
	}
	read_unlock(&root->lock);

	return ret;
}

static struct we_req_q *we_req_search(struct we_req_q_head *root,
		pid_t ppid)
{
	struct list_head *p;
	struct we_req_q *req, *ret = NULL;

	read_lock(&root->lock);
	list_for_each(p, &root->head) {
		req = list_entry(p, struct we_req_q, queue);
		if (req->data.we_obj_info->ppid == ppid) {
			ret = req;
			break;
		}
	}
	read_unlock(&root->lock);

	return ret;
}

static int check_we_pathsize(struct we_req_q *we_req, int size)
{
	if (size - sizeof(*we_req)
			> we_req->data.we_obj_info->pathsize)
		return 0;
	else
		return -1;
}

static unsigned long set_we_req_info(struct we_req_user *user,
		struct we_obj_info *info)
{
	unsigned long ret;

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
	ret = copy_to_user(user->path, info->path, info->pathsize + 1);
	if (ret != 0)
		return -EFAULT;
	return 0;
}

static ssize_t we_driver_read(struct file *file, char *buf,
		size_t size, loff_t *off)
{
	int ret;
	struct we_req_q *we_req;
	struct we_req_user *user;

	while (1) {
		ret = wait_event_interruptible(root->waitq,
				(we_req = get_alive_we_req(root)));
		if (ret < 0) {
			pr_info("WhiteEgret: %s: signal (%d)", __func__, ret);
			return 0;
		}

		if (we_req) {
			user = (struct we_req_user *)((void *)(buf));
			if (check_we_pathsize(we_req, size)) {
				pr_err("WhiteEgret: ");
				pr_err("Path length of exec is too long (%d).\n",
					we_req->data.we_obj_info->pathsize);
				return -EPERM;
			}

			set_we_req_info(user,
					we_req->data.we_obj_info);
			break;
		}

		pr_warn("WhiteEgret: %s: can not find we_req.\n", __func__);
	}

	pr_info("WhiteEgret: read %s.", we_req->data.we_obj_info->path);

	return sizeof(*user) + user->pathsize + 1;
}

static unsigned long set_we_ack(struct we_ack *to, struct we_ack *from)
{
	unsigned long ret;

	WE_COPY_FROM_USER(to->ppid, from->ppid, ret);
	if (ret != 0)
		return -EFAULT;
	WE_COPY_FROM_USER(to->permit, from->permit, ret);
	if (ret != 0)
		return -EFAULT;

	return 0;
}

static size_t send_ack(struct we_req_q *req, struct we_ack *ack)
{
	if (!req) {
		pr_warn("WhiteEgret: %s: can not find we_req.\n", __func__);
		return -EPERM;
	}
	req->permit = ack->permit;
	req->finish_flag = START_EXEC;
	wake_up_interruptible(&req->waitq);
	return sizeof(*ack);
}

static ssize_t we_driver_write(struct file *file, const char *buf,
		size_t size, loff_t *off)
{
	size_t ret;
	struct we_req_q *we_req;
	struct we_ack ack;

	set_we_ack(&ack, (struct we_ack *)((void *)buf));
	we_req = we_req_search(root, ack.ppid);
	ret = send_ack(we_req, &ack);
	pr_info("WhiteEgret: write %s.", we_req->data.we_obj_info->path);
	return ret;
}

static long we_driver_ioctl(struct file *file,
		unsigned int arg0, unsigned long arg1)
{
	return SUCCESS;
}

static int we_driver_release(struct inode *inode, struct file *filp)
{
	int ret = 0;

	ret = stop_we();
	pr_info("WhiteEgret: we_driver closed (%d)\n", ret);
	return ret;
}

static int we_driver_open(struct inode *inode, struct file *filp)
{
	root = start_we();
	if (!root)
		return -EPERM;
	return SUCCESS;
}

static const struct file_operations we_driver_fops = {
	.owner = THIS_MODULE,
	.read = we_driver_read,
	.write = we_driver_write,
	.unlocked_ioctl = we_driver_ioctl,
	.open =  we_driver_open,
	.release = we_driver_release,
};

static int we_driver_init(void)
{
	int ret;
	dev_t we_dev;
	struct device *we_device;

	ret = alloc_chrdev_region(&we_dev, 0, WE_MINOR, WE_DEV_NAME);
	if (ret < 0) {
		pr_err("WhiteEgret: ");
		pr_err("alloc_chrdev_region error: can not allocate chrdev.\n");
		return ret;
	}
	we_major = MAJOR(we_dev);

	we_class = class_create(THIS_MODULE, WE_CLASS_NAME);
	if (IS_ERR(we_class)) {
		pr_err("WhiteEgret: class_create error.\n");
		ret = PTR_ERR(we_class);
		goto failure_register;
	}

	we_device = device_create(we_class, NULL, we_dev, NULL, WE_DEV_NAME);
	if (IS_ERR(we_device)) {
		pr_err("WhiteEgret: device_create error.\n");
		ret = PTR_ERR(we_device);
		goto failure_class;
	}

	cdev_init(&we_cdev, &we_driver_fops);
	we_cdev.owner = THIS_MODULE;
	ret = cdev_add(&we_cdev, we_dev, WE_MINOR);
	if (ret < 0) {
		pr_err("WhiteEgret: cdev_add error: can not register chrdev.\n");
		goto failure_device;
	}

	pr_info("WhiteEgret: we_driver is installed.\n");
	rwlock_init(&resource_lock);
	return 0;

failure_device:
	device_destroy(we_class, we_dev);
failure_class:
	class_destroy(we_class);
failure_register:
	unregister_chrdev_region(we_dev, WE_MINOR);

	return ret;
}

static void we_driver_exit(void)
{
	dev_t we_dev;

	we_dev = MKDEV(we_major, WE_MINOR);
	device_destroy(we_class, we_dev);
	class_destroy(we_class);
	unregister_chrdev_region(we_dev, WE_MINOR);
	pr_info("WhiteEgret: we_driver is removed.\n");
}

module_init(we_driver_init);
module_exit(we_driver_exit);
