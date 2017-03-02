/*
 * Tox DHT bootstrap daemon.
 * Logging backend definition.
 */

/*
 * Copyright © 2017 The TokTok team.
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

#ifndef LOG_BACKEND_H
#define LOG_BACKEND_H

#include "log.h"

#include <stdarg.h>

typedef struct Log_Backend_Impl {
    void (*log_open)(void);
    void (*log_close)(void);
    void (*log_write)(LOG_LEVEL, const char *, va_list);
} Log_Backend_Impl;

#define LOG_BACKEND_IMPL(BACKEND) \
{ \
    log_backend_##BACKEND##_open, \
    log_backend_##BACKEND##_close, \
    log_backend_##BACKEND##_write \
}

#endif // LOG_BACKEND_H
