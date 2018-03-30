/*
 * WhiteEgret Linux Security Module
 *
 * Copyright (C) 2017-2018 Toshiba Corporation
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation, version 2.
 */

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/rwlock_types.h>
#include <linux/slab.h>
#include <linux/string.h>
#include "request.h"

struct we_req_q_head we_q_head;

static int match_we_req_data(struct we_req_data *data1,
		struct we_req_data *data2);

/**
 * we_req_q_head_init - Initialize the global variable we_q_head.
 *
 * Returns 0.
 */
int we_req_q_head_init(void)
{
	rwlock_init(&(we_q_head.lock));
	INIT_LIST_HEAD(&(we_q_head.head));
	init_waitqueue_head(&(we_q_head.waitq));

	return 0;
}

/**
 * we_req_q_push - Add queue to tail of the list.
 *
 * @queue: Pointer to we_req_q to be added to the list.
 *
 * Returns 0.
 */
int we_req_q_push(struct we_req_q *queue)
{
	write_lock(&(we_q_head.lock));
	list_add_tail(&(queue->queue), &we_q_head.head);
	write_unlock(&(we_q_head.lock));

	return 0;
}

/**
 * we_req_q_search - Search data in the list.
 *
 * @data: Pointer to we_req_data to be searched in the list.
 *
 * Returns pointer to data if data is found in the list,
 * NULL otherwise.
 */
struct we_req_q *we_req_q_search(struct we_req_data *data)
{
	struct list_head *p;
	struct we_req_q *req;

	read_lock(&(we_q_head.lock));

	list_for_each(p, &(we_q_head.head)) {
		req = list_entry(p, struct we_req_q, queue);

		if (match_we_req_data(data, &(req->data))) {
			read_unlock(&(we_q_head.lock));
			return req;
		}
	}

	read_unlock(&(we_q_head.lock));

	return NULL;
}

/**
 * we_req_q_init - Initialize queue.
 *
 * @req: Pointer to we_req_q to be initialized.
 * @info: Pointer to we_obj_info.
 *
 * Returns 0.
 */
int we_req_q_init(struct we_req_q *req, struct we_obj_info *info)
{
	req->finish_flag = STOP_EXEC;
	req->data.we_obj_info = info;
	req->permit = -EACCES;
	init_waitqueue_head(&req->waitq);

	return 0;
}

/**
 * we_req_q_pop - Delete queue in the list.
 *
 * Returns 0.
 */
int we_req_q_pop(struct we_req_q *queue)
{
	write_lock(&(we_q_head.lock));
	list_del(&queue->queue);
	write_unlock(&(we_q_head.lock));

	return 0;
}

/**
 * match_we_req_data - Compare two we_req_data data.
 *
 * @data1: Pointer to we_req_data
 * @data2: Pointer to we_req_data
 *
 * Returns 1 if ppid of both we_req_data data are equal,
 * 0 otherwise.
 */
static int match_we_req_data(struct we_req_data *data1,
		struct we_req_data *data2)
{
	if (data1->we_obj_info->ppid == data2->we_obj_info->ppid)
		return 1;

	return 0;
}

/**
 * we_req_q_cleanup - Cleaning up queues.
 *
 * Returns 0.
 */
int we_req_q_cleanup(void)
{
	struct list_head *p;
	struct we_req_q *req;

	write_lock(&(we_q_head.lock));
	list_for_each(p, &we_q_head.head) {
		req = list_entry(p, struct we_req_q, queue);
		req->finish_flag = START_EXEC;
		req->permit = -EINVAL;
	}
	write_unlock(&(we_q_head.lock));

	return 0;
}
