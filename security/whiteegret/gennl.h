/*
 * WhiteEgret Linux Security Module
 *
 * Copyright (C) 2017 Toshiba Corporation
 */

#ifndef _GENNL_H
#define _GENNL_H

#include <net/genetlink.h>
#include "we.h"

extern int from_pid;

/* handler */
int we_unspec(struct sk_buff *buf, struct genl_info *info);
int we_userregister(struct sk_buff *buf, struct genl_info *info);
int we_userunregister(struct sk_buff *buf, struct genl_info *info);
int we_execpermission(struct sk_buff *buf, struct genl_info *info);

/* register/unregister */
int we_netlink_register(void);
int we_netlink_unregister(void);

/* send message to user space */
int send_we_obj_info(struct we_obj_info *info);

/* manipulate sequence number */
void inc_seq(void);
int get_seq(void);

#endif  /* _GENNL_H */
