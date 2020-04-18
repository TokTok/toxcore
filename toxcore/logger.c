/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013,2015 Tox project.
 */

/*
 * Text logging abstraction.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "logger.h"

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>


struct Logger {
    logger_cb *callback;
    void *context;
    void *userdata;
};

#ifdef USE_STDERR_LOGGER
static const char *logger_level_name(Logger_Level level)
{
    switch (level) {
        case LOGGER_LEVEL_TRACE:
            return "TRACE";

        case LOGGER_LEVEL_DEBUG:
            return "DEBUG";

        case LOGGER_LEVEL_INFO:
            return "INFO";

        case LOGGER_LEVEL_WARNING:
            return "WARNING";

        case LOGGER_LEVEL_ERROR:
            return "ERROR";
    }

    return "<unknown>";
}

static void logger_stderr_handler(void *context, Logger_Level level, const char *file, int line, const char *func,
                                  const char *message, void *userdata)
{
    // GL stands for "global logger".
    fprintf(stderr, "[GL] %s %s:%d(%s): %s\n", logger_level_name(level), file, line, func, message);
}

static const Logger logger_stderr = {
    logger_stderr_handler,
    nullptr,
    nullptr,
};
#endif

/**
 * Public Functions
 */
Logger *logger_new(void)
{
    return (Logger *)calloc(1, sizeof(Logger));
}

void logger_kill(Logger *log)
{
    free(log);
}

void logger_callback_log(Logger *log, logger_cb *function, void *context, void *userdata)
{
    log->callback = function;
    log->context  = context;
    log->userdata = userdata;
}

void logger_write(const Logger *log, Logger_Level level, const char *file, int line, const char *func,
                  const char *format, ...)
{
    if (!log) {
#ifdef USE_STDERR_LOGGER
        log = &logger_stderr;
#else
        fprintf(stderr, "NULL logger not permitted.\n");
        abort();
#endif
    }

    if (!log->callback) {
        return;
    }

    // Only pass the file name, not the entire file path, for privacy reasons.
    // The full path may contain PII of the person compiling toxcore (their
    // username and directory layout).
    const char *filename = strrchr(file, '/');
    file = filename ? filename + 1 : file;
#if defined(_WIN32) || defined(__CYGWIN__)
    // On Windows, the path separator *may* be a backslash, so we look for that
    // one too.
    const char *windows_filename = strrchr(file, '\\');
    file = windows_filename ? windows_filename + 1 : file;
#endif

    // Format message
    char msg[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(msg, sizeof(msg), format, args);
    va_end(args);

    log->callback(log->context, level, file, line, func, msg, log->userdata);
}

void logger_api_write(const Logger *log, Logger_Level level, const char *file, int line, const char *func,
                      const char *format, va_list args)
{
    if (!log) {
#ifdef USE_STDERR_LOGGER
        log = &logger_stderr;
#else
        fprintf(stderr, "NULL logger not permitted.\n");
        abort();
#endif
    }

    if (!log->callback) {
        return;
    }

    // Only pass the file name, not the entire file path, for privacy reasons.
    // The full path may contain PII of the person compiling toxcore (their
    // username and directory layout).
    const char *filename = strrchr(file, '/');
    file = filename ? filename + 1 : file;
#if defined(_WIN32) || defined(__CYGWIN__)
    // On Windows, the path separator *may* be a backslash, so we look for that
    // one too.
    const char *windows_filename = strrchr(file, '\\');
    file = windows_filename ? windows_filename + 1 : file;
#endif

    // Format message
    char msg[1024];
    vsnprintf(msg, sizeof(msg), format, args);

    log->callback(log->context, level, file, line, func, msg, log->userdata);
}


/*
 * hook mutex function so we can nicely log them (to the NULL logger!)
 */
#if defined(__linux__)
#include <unistd.h>
#include <sys/syscall.h>
long syscall(long number, ...);
#define gettid() syscall(SYS_gettid)
#endif

int my_pthread_mutex_lock(pthread_mutex_t *mutex, const char *mutex_name, const char *file, int line, const char *func)
{
#if !(defined(_WIN32) || defined(__WIN32__) || defined(WIN32))
    pthread_t cur_pthread_tid = pthread_self();
    logger_write(NULL, LOGGER_LEVEL_DEBUG, file, line, func, "TID:%d:MTX_LOCK:S:%s:m=%p", (int32_t)cur_pthread_tid,
                 mutex_name, (void *)mutex);
#endif
    int ret = (pthread_mutex_lock)(mutex);
#if !(defined(_WIN32) || defined(__WIN32__) || defined(WIN32))
    logger_write(NULL, LOGGER_LEVEL_DEBUG, file, line, func, "TID:%d:MTX_LOCK:E:%s:m=%p", (int32_t)cur_pthread_tid,
                 mutex_name, (void *)mutex);
#endif
    return ret;
}

int my_pthread_mutex_unlock(pthread_mutex_t *mutex, const char *mutex_name, const char *file, int line,
                            const char *func)
{
#if !(defined(_WIN32) || defined(__WIN32__) || defined(WIN32))
    pthread_t cur_pthread_tid = pthread_self();
    logger_write(NULL, LOGGER_LEVEL_DEBUG, file, line, func, "TID:%d:MTX_unLOCK:S:%s:m=%p", (int32_t)cur_pthread_tid,
                 mutex_name, (void *)mutex);
#endif
    int ret = (pthread_mutex_unlock)(mutex);
#if !(defined(_WIN32) || defined(__WIN32__) || defined(WIN32))
    logger_write(NULL, LOGGER_LEVEL_DEBUG, file, line, func, "TID:%d:MTX_unLOCK:E:%s:m=%p", (int32_t)cur_pthread_tid,
                 mutex_name, (void *)mutex);
#endif
    return ret;
}



// ----------------------------
// ----------------------------
// ----------------------------
#ifdef LOGGER_DO_STACKTRACE_DEBUG_STUFF
// this code fragment shows how to print a stack trace (to stderr)
// on Linux using the functions provided by the GNU libc
#include <execinfo.h>
#include <libgen.h>
#include <unistd.h>

ssize_t readlink(const char *pathname, char *buf, size_t bufsiz);
int addr2line(void const *const addr, char *message_line);

/* Resolve symbol name and source location given an address */
int addr2line(void const *const addr, char *message_line)
{
    char addr2line_cmd[3000] = {0};
    char program_name[221] = {0};
    int dest_len = 220;

    if (readlink("/proc/self/exe", program_name, dest_len) == -1) {
        // problem reading our own binary's full pathname
        printf("__readlink PROBLEM-_\n");
        return 0;
    }

    /* have addr2line map the address to the relent line in the code */
    sprintf(addr2line_cmd, "echo '%s' |sed -e 's#.*(##'|sed -e 's#).*##'| xargs -L1 addr2line -f -p -e '%.256s'",
            message_line, program_name);

    /* This will print a nicely formatted string specifying the
     function and source line of the address */
    return system(addr2line_cmd);
}

#define MAX_STACK_FRAMES 10
void print_stacktrace()
{
    int i;
    int trace_size = 0;
    void *stack_traces[MAX_STACK_FRAMES];
    char **messages;


    trace_size = backtrace(stack_traces, MAX_STACK_FRAMES);
    messages = backtrace_symbols(stack_traces, trace_size);

    /* skip the first couple stack frames (as they are this function and
     our handler) and also skip the last frame as it's (always?) junk. */
    // for (i = 3; i < (trace_size - 1); ++i)
    // we'll use this for now so you can see what's going on
    for (i = 2; i < trace_size; ++i) {
        // printf("X%sX\n", messages[i]);
        addr2line(stack_traces[i], messages[i]);
    }

    if (messages) {
        free(messages);
    }
}
#endif
// ----------------------------
// ----------------------------
// ----------------------------

