/*
 * WhiteEgret Linux Security Module
 *
 * Copyright (C) 2017 Toshiba Corporation
 */

#include "dd_com.h"
#include "request.h"
#include "we.h"
#include "print_msg.h"

struct task_struct *from_task;

/**
 * start_we - Enable WhiteEgret.
 *
 * Returns pointer to we_req_q_head.
 */
struct we_req_q_head *start_we(void)
{
	if (from_task) {
		PRINT_WARNING("WhiteEgret has already started.\n");
		return NULL;
	}

	write_lock(&(we_q_head.lock));
	from_task = current;
	write_unlock(&(we_q_head.lock));

	return &we_q_head;
}
EXPORT_SYMBOL(start_we);

/**
 * stop_we - Disable WhiteEgret.
 *
 * Returns -EPERM if the task invoking this function is not valid,
 * 0 otherwise.
 */
int stop_we(void)
{
	if (!from_task) {
		PRINT_WARNING("WhiteEgret has not started.\n");
		return -EPERM;
	}
	if (from_task != current) {
		PRINT_WARNING("This task is not registered to WhiteEgret.\n");
		return -EPERM;
	}

	we_req_q_cleanup();

	write_lock(&(we_q_head.lock));
	from_task = NULL;
	write_unlock(&(we_q_head.lock));

	return 0;
}
EXPORT_SYMBOL(stop_we);

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
	 * then wake up it.
	 */
	if (waitqueue_active(&(we_q_head.waitq)))
		wake_up(&(we_q_head.waitq));

	return wait_event_interruptible_timeout(req->waitq,
			(req->finish_flag == START_EXEC),
			WERESULTTIMEOUT);
}
