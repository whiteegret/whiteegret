/*
 * WhiteEgret Linux Security Module
 *
 * Copyright (C) 2017 Toshiba Corporation
 */

#ifndef _GENNL_COMMON_H
#define _GENNL_COMMON_H

/* UWA stands for User's Whitelisting Application */

/* Netlink attributes */
enum {
	WE_A_UNSPEC,    /* unspecified message */
	WE_A_AUTHINFO,  /* authentication info for UWA registration */
	WE_A_SHORTNAME, /* short name for an object to be examined */
	WE_A_PATH,      /* full path for an object to be examined */
	WE_A_EXECPERMISSION, /* flag if the object is in the whitelist */
	__WE_A_MAX,
};

/* Number of netlink attributes */
#define WE_A_MAX (__WE_A_MAX - 1)

/* Name of genl_family */
#define WE_FAMILY_NAME "WhiteEgret"

/* Version number of genl_family */
#define WE_FAMILY_VERSION 1

/* Netlink commands */
enum {
	WE_C_UNSPEC,          /* unspecified message */
	WE_C_USERREGISTER,    /* register UWA */
	WE_C_USERUNREGISTER,
	WE_C_EXECPERMISSION,  /* execution permission */
	__WE_C_MAX,
};

/* Number of netlink commands */
#define WE_C_MAX (__WE_C_MAX - 1)

#endif  /* _GENNL_COMMON_H */
