/*
 * WhiteEgret Linux Security Module
 *
 * Copyright (C) 2017 Toshiba Corporation
 */

#ifndef _REQUEST_H
#define _REQUEST_H

#include <linux/sched.h>
#include <linux/wait.h>

#include "we.h"

struct we_req_q_head {
	struct list_head head;
	rwlock_t lock;
#ifdef CONFIG_SECURITY_WHITEEGRET_DRIVER
	wait_queue_head_t waitq;
#endif
};

#ifdef CONFIG_SECURITY_WHITEEGRET_DRIVER

#define STOP_EXEC  0
#define START_EXEC 1

extern struct we_req_q_head we_q_head;

/* Structure for information of request from kernel space to user space */
struct we_req_data {
	struct we_obj_info *we_obj_info;
};

struct we_req_q {
	struct list_head queue;
	int finish_flag;
	struct we_req_data data;
	int permit;
	wait_queue_head_t waitq;
};

int we_req_q_pop(struct we_req_q *queue);
int we_req_q_cleanup(void);

#else  /* CONFIG_SECURITY_WHITEEGRET_DRIVER */

#include <linux/completion.h>

/* Return values of searching queue of requests */
enum {
	WE_NOTFOUND_REQUEST,
	WE_FOUND_REQUEST
};

/* Structure for information of request from kernel space to user space */
struct we_req_data {
	char shortname[SHORTNAMELENGTH];  /* file name */
	u32 seq;                          /* sequence number */
};

/* Structure for queue of requests */
struct we_req_q {
	struct list_head queue;
	struct completion evt;
	struct we_req_data data;
};

int we_req_q_specific_pull(struct we_req_data *data);
int we_req_q_del(struct we_req_data *data);

#endif  /* CONFIG_SECURITY_WHITEEGRET_DRIVER */

int we_req_q_head_init(void);
int we_req_q_init(struct we_req_q *req, struct we_obj_info *info);
int we_req_q_push(struct we_req_q *queue);
struct we_req_q *we_req_q_search(struct we_req_data *data);

#endif  /* _REQUEST_H */
