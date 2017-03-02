/*
 * Tox DHT bootstrap daemon.
 * Logging utility with support of multiple logging backends.
 */

/*
 * Copyright © 2016-2017 The TokTok team.
 * Copyright © 2015-2016 Tox project.
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
#include "log.h"
#include "log_backend.h"
#include "log_backend_stdout.h"
#include "log_backend_syslog.h"

// Order of elements should correspond to the order from LOG_BACKEND enum
static const Log_Backend_Impl BACKENDS[] = {
    LOG_BACKEND_IMPL(syslog),
    LOG_BACKEND_IMPL(stdout)
};

#define INVALID_BACKEND (LOG_BACKEND)-1u
static LOG_BACKEND current_backend = INVALID_BACKEND;

bool log_open(LOG_BACKEND backend)
{
    if (current_backend != INVALID_BACKEND) {
        return false;
    }

    BACKENDS[backend].log_open();

    current_backend = backend;

    return true;
}

bool log_close(void)
{
    if (current_backend == INVALID_BACKEND) {
        return false;
    }

    BACKENDS[current_backend].log_close();

    current_backend = INVALID_BACKEND;

    return true;
}


bool log_write(LOG_LEVEL level, const char *format, ...)
{
    if (current_backend == INVALID_BACKEND) {
        return false;
    }

    va_list args;
    va_start(args, format);

    BACKENDS[current_backend].log_write(level, format, args);

    va_end(args);

    return true;
}
