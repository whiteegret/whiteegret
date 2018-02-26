/*
 * WhiteEgret Linux Security Module
 *
 * Copyright (C) 2017-2018 Toshiba Corporation
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation, version 2.
 */

#ifndef _WE_FS_H
#define _WE_FS_H

#include "request.h"
#include "we_fs_common.h"

extern struct task_struct *from_task;

int we_fs_init(void);

int send_we_obj_info(struct we_req_q *req);

#endif  /* _WE_FS_H */
