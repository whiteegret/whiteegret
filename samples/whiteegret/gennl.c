/*
 * WhiteEgret Linux Security Module
 *
 * Sample program of user's whitelisting application
 *
 * Copyright (C) 2017 Toshiba Corporation
 */

#include <errno.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/mngt.h>
#include <netlink/cache-api.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>

#include "we_common.h"
#include "gennl_common.h"
#include "gennl_user.h"
#include "checkwl.h"

uint16_t kerfamilyid;

/* attribute policy */
static struct nla_policy we_genl_policy[WE_A_MAX + 1] = {
	[WE_A_UNSPEC]       = { .type = NLA_STRING },
	[WE_A_AUTHINFO]     = { // .type = NLA_BINARY,  /* only kernel */
					.maxlen  = AUTHINFOLENGTH },
	[WE_A_SHORTNAME]    = { .type = NLA_STRING,
					.maxlen  = SHORTNAMELENGTH },
	[WE_A_PATH]         = { .type = NLA_STRING },
	[WE_A_EXECPERMISSION]       = { .type = NLA_FLAG },
};

/**
 * seq_num_no_check_callback - Disable checking sequence number.
 */
int seq_num_no_check_callback(struct nl_msg *msg, void *arg)
{
	return 0;
}

/**
 * we_user_execpermission_callback
 * - Callback function for examination whether the executable input
 *   to this function is included in whitelist or not.
 */
int we_user_execpermission_callback(struct nl_msg *msg, void *arg)
{
	struct recv_payload_st *recv_p_st;
	struct nlmsghdr *hdr;
	struct genlmsghdr *genhdr;
	struct nlattr *attrs[WE_A_MAX+1];
	int checkresult = 0;
	int rc;

	recv_p_st = (struct recv_payload_st *)arg;

	hdr = nlmsg_hdr(msg);
	genhdr = (struct genlmsghdr *)nlmsg_data(hdr);

	if (hdr->nlmsg_pid != 0) {
		rc = -EPERM;
		return rc;
	}

	if (hdr->nlmsg_type == recv_p_st->familyid) {
		if (genhdr->cmd == WE_C_EXECPERMISSION) {
			rc = nlmsg_validate(hdr, 0, WE_A_MAX,
					we_genl_policy);
			if (rc < 0) {
				nl_perror("nlmsg_validate");
				return rc;
			}
			genlmsg_parse(hdr, 0, attrs, WE_A_MAX,
					we_genl_policy);
			rc = check_whitelist(&checkresult, attrs);
			if (rc < 0) {
				perror("check_whitelist");
				return rc;
			}

			rc = respond_we_user_execpermission(
					recv_p_st->familyid,
					recv_p_st->nlhandle, checkresult,
					hdr->nlmsg_seq,
					nla_get_string(
						attrs[WE_A_SHORTNAME])
					);
			if (rc < 0) {
				perror("respond_we_user_execpermission");
				return rc;
			}
		} else {
			perror("receive msg with unknown command\n");
		}
		return NL_OK;
	}

	perror("receive msg with unknown family\n");
	return NL_SKIP;
}

/**
 * send_we_user_register - Callback function for registration
 *                             of user's whitelisting application.
 */
int send_we_user_register(uint16_t kerfamilyid, struct nl_handle *h,
		char *authinfo)
{
	struct nl_msg *msg;
	void *hdr;

	msg = nlmsg_alloc();
	if (msg == NULL) {
		nl_perror("nlmsg_alloc");
		return -1;
	}

	hdr = genlmsg_put(
			msg, NL_AUTO_PID, NL_AUTO_SEQ, kerfamilyid,
			0, NLM_F_ECHO, WE_C_USERREGISTER,
			WE_FAMILY_VERSION
			);
	if (hdr == NULL) {
		nl_perror("genlmsg_put");
		return -1;
	}

	if (nla_put(msg, WE_A_AUTHINFO, AUTHINFOLENGTH, authinfo) < 0) {
		nl_perror("nla_put: authinfo");
		return -1;
	}

	if (nl_send_auto_complete(h, msg) < 0) {
		nl_perror("nl_send_auto_complete");
		return -1;
	}

	nlmsg_free(msg);

	return 0;
}

/**
 * send_we_user_unregister - Callback function for unregistration
 *                               of user's whitelisting application.
 */
int send_we_user_unregister(uint16_t kerfamilyid, struct nl_handle *h,
		char *authinfo)
{
	struct nl_msg *msg;
	void *hdr;

	msg = nlmsg_alloc();
	if (msg == NULL) {
		nl_perror("nlmsg_alloc");
		return -1;
	}

	hdr = genlmsg_put(
			msg, NL_AUTO_PID, NL_AUTO_SEQ, kerfamilyid,
			0, NLM_F_ECHO, WE_C_USERUNREGISTER,
			WE_FAMILY_VERSION
			);
	if (hdr == NULL) {
		nl_perror("genlmsg_put");
		return -1;
	}

	if (nla_put(msg, WE_A_AUTHINFO, AUTHINFOLENGTH, authinfo) < 0) {
		nl_perror("nla_put: authinfo");
		return -1;
	}

	if (nl_send_auto_complete(h, msg) < 0) {
		nl_perror("nl_send_auto_complete");
		return -1;
	}

	nlmsg_free(msg);

	return 0;
}

/**
 * respond_we_user_execpermission - Send response to kernel space.
 */
int respond_we_user_execpermission(uint16_t kerfamilyid,
		struct nl_handle *h, int checkresult, unsigned int seq,
		char *shortname)
{
	struct nl_msg *msg;
	void *hdr;

	msg = nlmsg_alloc();
	if (msg == NULL) {
		nl_perror("nlmsg_alloc");
		return -1;
	}

	hdr = genlmsg_put(
			msg, NL_AUTO_PID, seq, kerfamilyid,
			0, NLM_F_ECHO, WE_C_EXECPERMISSION,
			WE_FAMILY_VERSION
			);
	if (hdr == NULL) {
		nl_perror("genlmsg_put");
		return -1;
	}

	if (nla_put_string(msg, WE_A_SHORTNAME, shortname) < 0) {
		nl_perror("nla_put_string");
		return -1;
	}

	if (checkresult != -EPERM) {
		if (nla_put_flag(msg, WE_A_EXECPERMISSION) < 0) {
			nl_perror("nla_put_flag: execpermission");
			return -1;
		}
	}

	if (nl_send_auto_complete(h, msg) < 0) {
		nl_perror("nl_send_auto_complete");
		return -1;
	}

	nlmsg_free(msg);

	return 0;
}

