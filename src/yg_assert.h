/*
 * yg_assert.h
 *
 *  Created on: 2016-06-15
 *      Author: apple
 */

#ifndef YG_ASSERT_H_
#define YG_ASSERT_H_

#include "yg_log.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <strings.h>
#include <string.h>
#include <regex.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>


#define YG_ASSERT_RET(flag, ret)	\
do { \
	if((flag) == 0) {\
		YG_ERR((char *)"ERR");	\
		return ret;	\
	}\
}while(0)


#define YG_ASSERT_RET_INFO(flag, ret, info)	\
do { \
	if((flag) == 0) {\
		YG_ERR((char *)"ERR: %s", info);	\
		return ret;	\
	}\
}while(0)


#define YG_ASSERT_ERR(flag, ret)	\
do { \
	if((flag) == 0) {\
		YG_ERR("ERR(%s)", strerror(errno));	\
		return ret;	\
	}\
}while(0)


#define YG_MALLOC(p, size, type) \
do {\
	p = (type)malloc(size);  \
	if(p == NULL) { \
		YG_ERR("malloc(%d) ERR(%s)", size, strerror(errno));  \
	} else { \
		memset(p, 0, size); \
	} \
} while(0)


#endif /* YG_ASSERT_H_ */
