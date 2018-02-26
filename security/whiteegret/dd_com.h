/*
 * WhiteEgret Linux Security Module
 *
 * Copyright (C) 2017 Toshiba Corporation
 */

#ifndef _DD_COM_H
#define _DD_COM_H

#include "request.h"

extern struct task_struct *from_task;

extern struct we_req_q_head *start_we(void);
extern int stop_we(void);

int send_we_obj_info(struct we_req_q *req);

#endif  /* _DD_COM_H */
