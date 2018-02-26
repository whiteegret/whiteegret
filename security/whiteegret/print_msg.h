/*
 * WhiteEgret Linux Security Module
 *
 * Copyright (C) 2017 Toshiba Corporation
 */

#ifndef _PRINT_MSG_H
#define _PRINT_MSG_H

#include <linux/kernel.h>

#define __STR(x) #x
#define __STR2(x) __STR(x)
#define ERROR_MSG "error %d at "__STR2(__LINE__)" on " __STR2(__FILE__)"\n"
#define PRINT_ERROR(errno) pr_err("WhiteEgret: " ERROR_MSG, errno)
#define PRINT_WARNING(fmt, ...) pr_warn("WhiteEgret: " fmt, ##__VA_ARGS__)
#define PRINT_INFO(fmt, ...) pr_info("WhiteEgret: " fmt, ##__VA_ARGS__)

#endif
