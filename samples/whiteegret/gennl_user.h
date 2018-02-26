/** @file gennl_user.h
 * @brief Header file for netlink generic functionalities used in
 * user's whitelisting application.
 * Definitions in this file are specific for user's whitelisting
 * application.
 */

#ifndef _GENNL_USER_H
#define _GENNL_USER_H

#include <netlink/genl/genl.h>

/* callback function */
int seq_num_no_check_callback(struct nl_msg *msg, void *arg);
int we_user_execpermission_callback(struct nl_msg *msg, void *arg);

/* methods for send a message to kernel space */
int send_we_user_register(uint16_t kerfamilyid, struct nl_handle *h,
		char *authinfo);
int send_we_user_unregister(uint16_t kerfamilyid, struct nl_handle *h,
		char *authinfo);
int respond_we_user_execpermission(uint16_t kerfamilyid,
		struct nl_handle *h, int checkresult, unsigned int seq,
		char *shortname);

/* datatype for passing to receive callback */
struct recv_payload_st {
	uint16_t familyid;
	struct nl_handle *nlhandle;
};

#endif  /* _GENNL_USER_H */
