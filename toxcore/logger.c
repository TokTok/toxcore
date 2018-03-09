/*
 * Text logging abstraction.
 */

/*
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013,2015 Tox project.
 *
 * This file is part of Tox, the free peer to peer instant messenger.
 *
 * Tox is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Tox is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "env.h"
#include "logger.h"

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>


struct Logger {
    logger_cb *callback;
    void *context;
    void *userdata;
};

#ifdef USE_STDERR_LOGGER
static const char *logger_level_name(LOGGER_LEVEL level)
{
    switch (level) {
        case LOG_TRACE:
            return "TRACE";

        case LOG_DEBUG:
            return "DEBUG";

        case LOG_INFO:
            return "INFO";

        case LOG_WARNING:
            return "WARNING";

        case LOG_ERROR:
            return "ERROR";
    }

    return "<unknown>";
}

static void logger_stderr_handler(void *context, LOGGER_LEVEL level, const char *file, int line, const char *func,
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
    return (Logger *)env_calloc(1, sizeof(Logger));
}

void logger_kill(Logger *log)
{
    env_free(log);
}

void logger_callback_log(Logger *log, logger_cb *function, void *context, void *userdata)
{
    log->callback = function;
    log->context  = context;
    log->userdata = userdata;
}

void logger_write(const Logger *log, LOGGER_LEVEL level, const char *file, int line, const char *func,
                  const char *format, ...)
{
    if (!log) {
#ifdef USE_STDERR_LOGGER
        log = &logger_stderr;
#else
        assert(!"NULL logger not permitted");
#endif
    }

    if (!log->callback) {
        return;
    }

    /* Format message */
    char msg[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(msg, sizeof msg, format, args);
    va_end(args);

    log->callback(log->context, level, file, line, func, msg, log->userdata);
}
