/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013-2015 Tox project.
 */
#ifndef C_TOXCORE_TOXAV_HACKS_H
#define C_TOXCORE_TOXAV_HACKS_H

#include "bwcontroller.h"
#include "msi.h"
#include "rtp.h"

void *call_get(void *av, uint32_t friend_number);
RTPSession *rtp_session_get(void *call, int payload_type);
MSISession *tox_av_msi_get(void *av);
BWController *bwc_controller_get(void *call);

#endif // C_TOXCORE_TOXAV_HACKS_H
