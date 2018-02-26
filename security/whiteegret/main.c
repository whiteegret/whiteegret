/*
 * WhiteEgret Linux Security Module
 *
 * Copyright (C) 2017 Toshiba Corporation
 */

#include <linux/semaphore.h>
#include <linux/binfmts.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/mman.h>
#include "we_common.h"
#include "we.h"
#include "request.h"
#include "print_msg.h"

#ifdef CONFIG_SECURITY_WHITEEGRET_DRIVER

#include <linux/sched.h>
#include <linux/module.h>
#include <linux/slab.h>
#include "dd_com.h"

#else

#include "gennl.h"
#include "returntoexec.h"

struct we_req_data reqdata;  /* data of executable */
struct semaphore we_result_lock;
int result = -1;                 /* result of matching to white list */

#endif

static int send_receive_we_obj_info(
		struct we_obj_info *we_obj_info, int *checkresult);

/**
 * we_specific_init - Initialize netlink and semaphore.
 *
 * Returns 0.
 */
int we_specific_init(void)
{
#ifndef CONFIG_SECURITY_WHITEEGRET_DRIVER
	int rc = 0;

	rc = we_netlink_register();
	if (rc < 0) {
		PRINT_ERROR(rc);
		return rc;
	}

	sema_init(&we_result_lock, 1);
#endif
	we_req_q_head_init();

	return 0;
}

/**
 * we_specific_exit - Close netlink.
 *
 * Returns 0.
 */
int we_specific_exit(void)
{
#ifndef CONFIG_SECURITY_WHITEEGRET_DRIVER
	we_netlink_unregister();
#endif

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
		PRINT_ERROR(rc);
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
			PRINT_ERROR(rc);
			goto failure;
		}
		pathnamebuf = new_pathnamebuf;
	}
	if (unlikely(pathsize >= MAXPATHSIZE)) {
		rc = -ENOMEM;
		PRINT_ERROR(rc);
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
	we_obj_info.pid = current->pid;
#ifdef CONFIG_SECURITY_WHITEEGRET_DRIVER
	we_obj_info.pathsize = strlen(pathname);
	we_obj_info.ppid = current->tgid;
#endif

#ifndef CONFIG_SECURITY_WHITEEGRET_DRIVER
	rc = down_timeout(&we_result_lock, WERESULTTIMEOUT);
	if (rc != 0)
		goto failure;
	inc_seq();
#endif
	rc = send_receive_we_obj_info(&we_obj_info, &checkresult);
	if (rc < 0)
		goto failure;

	rc = checkresult;

	if (rc == -EPERM)
		PRINT_WARNING("block %s.\n", pathname);
	else
		PRINT_INFO("permit %s.\n", pathname);

#ifndef CONFIG_SECURITY_WHITEEGRET_DRIVER
	up(&we_result_lock);
#endif

failure:
	if (pathnamebuf != NULL) {
		kfree(pathnamebuf);
		pathnamebuf = NULL;
	}

	if ((rc != 0) && (rc != -EPERM))
		PRINT_WARNING("Checking white list does not work.\n");

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
			PRINT_ERROR(rc);
			goto failure;
		}
	}

#ifdef CONFIG_SECURITY_WHITEEGRET_DRIVER

	for (i = 0; i < MAXCOMRETRY; i++) {
		rc = send_we_obj_info(&req);

		if (likely(req.finish_flag == START_EXEC)) {
			break;
		} else if (unlikely(rc == -ERESTARTSYS)) {
			rc = -EINVAL;
			break;
		}
	}

	we_req_q_pop(&req);

	if (unlikely(i >= MAXCOMRETRY) && req.finish_flag != START_EXEC) {
		rc = -EINVAL;
		PRINT_ERROR(rc);
	}

	*checkresult = req.permit;

	return rc;

#else

	for (i = 0; i < MAXCOMRETRY; i++) {
		rc = send_we_obj_info(we_obj_info);
		if (rc < 0)
			continue;

		rc = wait_for_completion_interruptible_timeout(&(req.evt),
				WEGENNLTIMEOUT);
		if (rc <= 0) {
			if (unlikely(rc == -ERESTARTSYS)) {
				we_req_q_del(&(req.data));
				rc = -EINVAL;
				PRINT_ERROR(rc);
				goto failure;
			}
			if (rc == 0)
				rc = -ETIMEDOUT;
			continue;
		} else {
			break;
		}
	}

	if (unlikely(i >= MAXCOMRETRY)) {
		we_req_q_del(&(req.data));
		rc = -EINVAL;
		PRINT_ERROR(rc);
		goto failure;
	}

	*checkresult = result;

	return 0;

#endif  /* CONFIG_SECURITY_WHITEEGRET_DRIVER */

failure:
#ifndef CONFIG_SECURITY_WHITEEGRET_DRIVER
	up(&we_result_lock);
#endif
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
#ifdef CONFIG_SECURITY_WHITEEGRET_DRIVER
	if (unlikely(!from_task))
#else
	if (unlikely(from_pid == -1))
#endif
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
		unsigned long reqprot, unsigned long flags) {
#ifdef CONFIG_SECURITY_WHITEEGRET_DRIVER
	if (unlikely(!from_task))
#else
	if (unlikely(from_pid == -1))
#endif
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

#ifndef CONFIG_SECURITY_WHITEEGRET_DRIVER

/**
 * returntoexec - Record matching data and result.
 *
 * @result_: Result whether targeted object is included in the white list.
 * @reqdata_: Pointer to struct we_req_data.
 *
 * Returns 0.
 */
int returntoexec(int result_, struct we_req_data *reqdata_)
{
	if (!result_)
		result = -EPERM;
	else
		result = 0;
	memcpy(&reqdata, reqdata_, sizeof(struct we_req_data));

	return 0;
}

#endif
