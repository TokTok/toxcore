/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013-2015 Tox project.
 */
#ifndef C_TOXCORE_TOXAV_HACKS_H
#define C_TOXCORE_TOXAV_HACKS_H

#include "bwcontroller.h"
#include "msi.h"
#include "rtp.h"

#ifndef TOXAV_CALL_DEFINED
#define TOXAV_CALL_DEFINED
typedef struct ToxAVCall ToxAVCall;
#endif /* TOXAV_CALL_DEFINED */

ToxAVCall *call_get(ToxAV *av, uint32_t friend_number);
RTPSession *rtp_session_get(ToxAVCall *call, int payload_type);
MSISession *tox_av_msi_get(ToxAV *av);
BWController *bwc_controller_get(void *call);
Mono_Time *toxav_get_av_mono_time(ToxAV *toxav);

#endif // C_TOXCORE_TOXAV_HACKS_H
