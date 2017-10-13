#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <stdarg.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "yg_log.h"

#define LOG_FILE_MAX_SIZE (1000 * 1024 * 1024)


char is_file_output = 0;
char logPrefixSet = 0;
char logPrefix[512];
int curLogLevel = CUR_LOG_LEVEL;

FILE *logFp = NULL;

void log_setlevel(int level)
{
    curLogLevel = level;
}

void logfile_open()
{
    is_file_output = 1;
}

void logfile_set_prefix(const char *prefix)
{
    if(prefix == NULL) return;

    logPrefixSet = 1;
    snprintf(logPrefix, sizeof(logPrefix) - 1, "%s", prefix);
}

int logfile_check_need_open()
{
    if(logFp == NULL) {
        if(logPrefixSet == 0) 
            snprintf(logPrefix, sizeof(logPrefix) - 1, "../log/log");
        return 1;
    }

    struct stat statInfo;
    if(fstat(fileno(logFp), &statInfo)) {
        fprintf(stderr, "%s::%s(%d) err: %s", __FILE__, __FUNCTION__, __LINE__, strerror(errno));
        return -1;
    }

    if(statInfo.st_size < LOG_FILE_MAX_SIZE) return 0;

    return 1;
}

/*
 *  return 0 | -1 
 */   
int logfile_open_check()
{
    int iRet = logfile_check_need_open();
    if(iRet != 1) return iRet;

    pthread_mutex_t mutex;
    pthread_mutex_init(&mutex, NULL);

    pthread_mutex_lock(&mutex);

    iRet = logfile_check_need_open();
    if(iRet != 1) {
        pthread_mutex_unlock(&mutex);
        return iRet;
    }

    char logFname[512];
    char newLogFname[512];
    int i = 8;
    if(logFp != NULL) {
        while(i >= 0) {
            snprintf(logFname, sizeof(logFname) - 1, "%s_%d.log", logPrefix, i);
            snprintf(newLogFname, sizeof(newLogFname) - 1, "%s_%d.log", logPrefix, i + 1);
            rename(logFname, newLogFname);

            i -= 1;
        }
        fclose(logFp);
    }
    else {
        snprintf(logFname, sizeof(logFname) - 1, "%s_%d.log", logPrefix, 0);
    }

    logFp = fopen(logFname, "a+");
    if(logFp == NULL) {
        fprintf(stderr, "fopen(%s) err(%s)", logFname, strerror(errno));
        iRet = -1;
    }

    dup2(fileno(logFp), STDOUT_FILENO);
    dup2(fileno(logFp), STDERR_FILENO);

    pthread_mutex_unlock(&mutex);
    return iRet == -1 ? -1 : 0;
}

void logfile_output(const char *log)
{
    if(log == NULL) return;

    int iRet = logfile_open_check();
    if(iRet == -1){
        fprintf(stderr, "logfile_open_check ERR\n");
        return;
    }

    fprintf(logFp, "%s\n", log);
    fflush(logFp);
}

char* get_log_level(int level, char *msg, unsigned int msgSize)
{
	if(level == T_LOG_TRACE) {
		snprintf(msg, msgSize, "TRACE");
	}
	else if(level == T_LOG_DBG) {
		snprintf(msg, msgSize, "DBG");
	}
	else if(level == T_LOG_INFO) {
		snprintf(msg, msgSize, "INFO");
	}
	else if(level == T_LOG_ERR) {
		snprintf(msg, msgSize, "ERR");
	}
	else {
		snprintf(msg, msgSize, "UNKNOWN");
	}

	return msg;
}

char* get_log_time(char *tmStr, unsigned int tmSize)
{
	time_t ms = time(NULL);
	struct tm *tmObj = localtime(&ms);

	int year = tmObj->tm_year + 1900;


	snprintf(tmStr, tmSize, "%d%02d%02d_%02d:%02d:%02d", tmObj->tm_year + 1900, tmObj->tm_mon + 1, tmObj->tm_mday,
			tmObj->tm_hour, tmObj->tm_min, tmObj->tm_sec);
	return tmStr;
}

void log_output(int level, char *file, char *fun, int line, char *fmt, ...)
{
	char levelStr[16];
	char tmStr[32];
	char msg[4096];

	msg[sizeof(msg) - 1] = 0;
	int idx = snprintf(msg, sizeof(msg) - 1, "[%d][%s][%s]%s::%s(%d):",
			getpid(), get_log_time(tmStr, sizeof(tmStr) - 1),
			get_log_level(level, levelStr, sizeof(levelStr) - 1),
			file, fun, line);
	if(idx < 0) return;

	va_list ap;
	va_start(ap, fmt);
	vsnprintf(msg + idx, sizeof(msg) - idx - 1, fmt, ap);
	va_end(ap);

    if(is_file_output == 1) 
        logfile_output(msg);
    else
        fprintf(stderr, "%s\n", msg);
}
