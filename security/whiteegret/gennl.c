/*
 * WhiteEgret Linux Security Module
 *
 * Copyright (C) 2017 Toshiba Corporation
 */

#include <linux/pid.h>
#include <linux/cred.h>
#include <linux/security.h>
#include <net/genetlink.h>

#include "auth.h"
#include "gennl_common.h"
#include "gennl.h"
#include "returntoexec.h"
#include "we_common.h"
#include "we.h"
#include "request.h"
#include "print_msg.h"

/* global variables */
int from_pid = -1;      /* pid of user's whitelisting application */
struct net *from_net;
u32 seq;		/* sequence number */

/* attribute policy */
static struct nla_policy we_genl_policy[WE_A_MAX + 1] = {
	[WE_A_UNSPEC]       = { .type = NLA_STRING },
	[WE_A_AUTHINFO]     = { .type = NLA_BINARY,
					.len  = AUTHINFOLENGTH },
	[WE_A_SHORTNAME]    = { .type = NLA_STRING,
					.len  = SHORTNAMELENGTH },
	[WE_A_PATH]         = { .type = NLA_STRING },
	[WE_A_EXECPERMISSION]       = { .type = NLA_FLAG },
};

/* operation definition */
static struct genl_ops we_gnl_opses[] = {
	{
		.cmd    = WE_C_UNSPEC,
		.flags  = 0,
		.policy = we_genl_policy,
		.doit   = we_unspec,
		.dumpit = NULL,
	},
	{
		.cmd    = WE_C_USERREGISTER,
		.flags  = 0,
		.policy = we_genl_policy,
		.doit   = we_userregister,
		.dumpit = NULL,
	},
	{
		.cmd    = WE_C_USERUNREGISTER,
		.flags  = 0,
		.policy = we_genl_policy,
		.doit   = we_userunregister,
		.dumpit = NULL,
	},
	{
		.cmd    = WE_C_EXECPERMISSION,
		.flags  = 0,
		.policy = we_genl_policy,
		.doit   = we_execpermission,
		.dumpit = NULL,
	},
};

/* family definition */
static struct genl_family we_gnl_family = {
	.name = WE_FAMILY_NAME,
	.version = WE_FAMILY_VERSION,
	.maxattr = WE_A_MAX,
	.ops = we_gnl_opses,
	.n_ops = ARRAY_SIZE(we_gnl_opses),
	.module = THIS_MODULE,
};

/**
 * we_netlink_register - Initialize netlink.
 *
 * Returns 0 if succeeded, < 0 otherwise.
 */
int we_netlink_register(void)
{
	int rc;

	PRINT_INFO("%s starts.\n", __func__);

	rc = genl_register_family(&we_gnl_family);
	if (rc != 0) {
		PRINT_ERROR(rc);
		return rc;
	}

	from_net = kmalloc(sizeof(struct net), GFP_KERNEL);
	if (!from_net) {
		rc = -ENOMEM;
		PRINT_ERROR(rc);
		return rc;
	}

	PRINT_WARNING("Netlink is registered by WhiteEgret.\n");

	return 0;
}

/**
 * we_netlink_unregister - Close netlink.
 *
 * Returns 0 if succeeded, < 0 otherwise.
 */
int we_netlink_unregister(void)
{
	int rc;

	PRINT_INFO("%s starts.\n", __func__);

	rc = genl_unregister_family(&we_gnl_family);
	if (rc != 0) {
		PRINT_ERROR(rc);
		return rc;
	}

	if (from_net != NULL) {
		kfree(from_net);
		from_net = NULL;
	}

	PRINT_WARNING("Netlink is unregistered by WhiteEgret.\n");

	return 0;
}

/**
 * we_unspec - Receive handler for unspecified.
 *
 * @buf: Pointer to struct sk_buff.
 * @info: Pointer to struct genl_info.
 *
 * Returns 0.
 */
int we_unspec(struct sk_buff *buf, struct genl_info *info)
{
	PRINT_INFO("Some message is handled at %s.\n", __func__);

	/* do something if necessary */

	return 0;
}

/**
 * we_userregister - Register user's whitelisting application.
 *
 * @buf: Pointer to struct sk_buff.
 * @info: Pointer to struct genl_info.
 *
 * Returns 0 if succeeded, < 0 otherwise.
 */
int we_userregister(struct sk_buff *buf, struct genl_info *info)
{
	int rc;
	struct pid *usrpid;
	struct task_struct *usrtask;
#ifdef CONFIG_NET_NS
	const struct cred *usrcred;
#endif

	PRINT_INFO("Some message is handled at %s.\n", __func__);

	if (from_pid != -1) {
		PRINT_WARNING
			("The pid %d is already registered to WhiteEgret.\n",
				from_pid);
		rc = -EACCES;
		PRINT_ERROR(rc);
		return rc;
	}

	usrpid = find_get_pid(info->snd_portid);
	if (usrpid == NULL) {
		rc = -EACCES;
		PRINT_ERROR(rc);
		return rc;
	}

	usrtask = get_pid_task(usrpid, PIDTYPE_PID);
	if (usrtask == NULL) {
		rc = -EACCES;
		PRINT_ERROR(rc);
		return rc;
	}

#ifdef CONFIG_NET_NS
	usrcred = get_task_cred(usrtask);
	if (usrcred == NULL) {
		rc = -EACCES;
		PRINT_ERROR(rc);
		return rc;
	}

	if ((security_capable(usrcred,  genl_info_net(info)->user_ns,
					CAP_NET_ADMIN)) != 0) {
		rc = -EACCES;
		PRINT_ERROR(rc);
		return rc;
	}
#endif

	rc = userproc_auth((char *)nla_data(info->attrs[WE_A_AUTHINFO]));
	if (rc <= 0) {
		PRINT_ERROR(rc);
		return rc;
	}

	from_pid = info->snd_portid;
	memcpy(from_net, genl_info_net(info), sizeof(struct net));

	seq = info->snd_seq;

	PRINT_WARNING("The pid %d is registered to WhiteEgret.\n", from_pid);

	return 0;
}

/**
 * we_userunregister - Unregister user's whitelisting application
 *				invoked by itself.
 *
 * @buf: Pointer to struct sk_buff.
 * @info: Pointer to struct genl_info.
 *
 * Returns 0 if succeeded, < 0 otherwise.
 */
int we_userunregister(struct sk_buff *buf, struct genl_info *info)
{
	int rc;

	PRINT_INFO("Some message is handled at %s.\n", __func__);

	if (from_pid != info->snd_portid) {
		rc = -EACCES;
		PRINT_ERROR(rc);
		return rc;
	}

	rc = userproc_auth((char *)nla_data(info->attrs[WE_A_AUTHINFO]));
	if (rc <= 0) {
		PRINT_ERROR(rc);
		return rc;
	}

	PRINT_WARNING("The pid %d is unregistered to WhiteEgret.\n", from_pid);

	from_pid = -1;

	return 0;
}

/**
 * we_execpermission - Receive handler for execution permission.
 *
 * @buf: Pointer to struct sk_buff.
 * @info: Pointer to struct genl_info.
 *
 * Returns 0 if succeeded, < 0 otherwise.
 */
int we_execpermission(struct sk_buff *buf, struct genl_info *info)
{
	int rc = 0;
	struct we_req_data data;

	PRINT_INFO("Some message is handled at %s.\n", __func__);

	if (from_pid != info->snd_portid) {
		rc = -EACCES;
		PRINT_ERROR(rc);
		return rc;
	}

	data.seq = info->snd_seq;
	memcpy(&(data.shortname), nla_data(info->attrs[WE_A_SHORTNAME]),
			SHORTNAMELENGTH);
	if (we_req_q_search(&data) == NULL) {
		PRINT_INFO("(%s, %d) is not waiting for execution.\n",
				data.shortname, data.seq);
		return 0;
	}

	rc = returntoexec(nla_get_flag(info->attrs[WE_A_EXECPERMISSION]),
			&data);
	if (rc != 0) {
		PRINT_ERROR(rc);
		return rc;
	}

	we_req_q_specific_pull(&data);

	PRINT_INFO("%s done (%s, %d).\n", __func__, data.shortname, data.seq);

	return 0;
}

/**
 * send_we_obj_info - Send request for matching white list.
 *
 * @we_info: Pointer to struct we_obj_info.
 *
 * Returns 0 if succeeded, < 0 otherwise.
 */
int send_we_obj_info(struct we_obj_info *we_info)
{
	int rc = 0;
	void *msg_head;
	struct sk_buff *send_skb;

	if ((from_pid == -1) || (from_net == NULL)) {
		rc = -EINVAL;
		PRINT_ERROR(rc);
		return rc;
	}

	send_skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (send_skb == NULL) {
		rc = -ENOMEM;
		PRINT_ERROR(rc);
		return rc;
	}

	msg_head = genlmsg_put(send_skb, 0, seq, &we_gnl_family, 0,
			WE_C_EXECPERMISSION);
	if (msg_head == NULL) {
		rc = -ENOMEM;
		PRINT_ERROR(rc);
		return rc;
	}

	rc = nla_put_string(send_skb, WE_A_SHORTNAME,
			we_info->shortname);
	if (rc != 0) {
		PRINT_ERROR(rc);
		return rc;
	}

	rc = nla_put_string(send_skb, WE_A_PATH, we_info->path);
	if (rc != 0) {
		PRINT_ERROR(rc);
		return rc;
	}

	genlmsg_end(send_skb, msg_head);

	PRINT_INFO("Msg (%s, %s) sent to the pid %d (current process: %d)\n",
			we_info->shortname, we_info->path,
			from_pid, we_info->pid);

	rc = genlmsg_unicast(from_net, send_skb, from_pid);
	if (rc != 0) {
		PRINT_ERROR(rc);
		return rc;
	}

	return 0;
}

/**
 * inc_seq - Increment sequence number.
 */
void inc_seq(void)
{
	seq += 1;
}

/**
 * get_seq - Return sequence number.
 *
 * Returns sequence number.
 */
int get_seq(void)
{
	return seq;
}
