/*
 * yg_log.h
 *
 *  Created on: 2016-06-16
 *      Author: yegui
 */

#ifndef YG_LOG_H_
#define YG_LOG_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef enum LogLevel
{
	T_LOG_TRACE = 0,
	T_LOG_DBG = 1,
	T_LOG_INFO = 2,
	T_LOG_ERR = 3,
}LogLevel;

#ifdef LOG_TRACE
#define CUR_LOG_LEVEL T_LOG_TRACE
#endif

#ifdef LOG_DEBUG
#define CUR_LOG_LEVEL T_LOG_DBG
#endif

#ifdef LOG_INFO
#define CUR_LOG_LEVEL T_LOG_INFO
#endif

#ifdef LOG_ERR
#define CUR_LOG_LEVEL T_LOG_ERR
#endif

#ifndef CUR_LOG_LEVEL
#define CUR_LOG_LEVEL T_LOG_INFO
#endif

extern int curLogLevel;


void log_output(int level, char *file, char *fun, int line, char *fmt, ...);
void log_setlevel(int level);

void logfile_open();
void logfile_set_prefix(const char *prefix);

#ifdef  YG_CLOSE_LOG
#define YG_LOG(level, fmt, ...)
#else

#define YG_LOG(level, fmt, ...) \
do {                            \
	if(level >= curLogLevel) 	\
		log_output(level, (char *)__FILE__, (char *)__FUNCTION__, __LINE__, (char *)fmt, ## __VA_ARGS__); \
} while(0)

#endif

#define YG_TRACE(fmt, ...)  	YG_LOG(T_LOG_TRACE, 	fmt, ## __VA_ARGS__)
#define YG_DBG(fmt, ...)  		YG_LOG(T_LOG_DBG, 	fmt, ## __VA_ARGS__)
#define YG_INFO(fmt, ...)  		YG_LOG(T_LOG_INFO, 		fmt, ## __VA_ARGS__)
#define YG_ERR(fmt, ...)  		YG_LOG(T_LOG_ERR, 		fmt, ## __VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif /* YG_LOG_H_ */
