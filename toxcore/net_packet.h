/*
 * Packet types.
 */

/*
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013-2016 Tox project.
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


#ifndef NET_PACKET_H
#define NET_PACKET_H

/* Packets in this range are reserved for net_crypto internal use. */
#define PACKET_ID_RANGE_RESERVED_START 0
#define PACKET_ID_RANGE_RESERVED_END 15
/* Packets in this range are reserved for Messenger use. */
#define PACKET_ID_RANGE_LOSSLESS_START 16
#define PACKET_ID_RANGE_LOSSLESS_NORMAL_START 16
#define PACKET_ID_RANGE_LOSSLESS_NORMAL_END 159
/* Packets in this range can be used for anything. */
#define PACKET_ID_RANGE_LOSSLESS_CUSTOM_START 160
#define PACKET_ID_RANGE_LOSSLESS_CUSTOM_END 191
#define PACKET_ID_RANGE_LOSSLESS_END 191
/* Packets in this range are reserved for AV use. */
#define PACKET_ID_RANGE_LOSSY_START 192
#define PACKET_ID_RANGE_LOSSY_AV_START 192
#define PACKET_ID_RANGE_LOSSY_AV_SIZE 8
#define PACKET_ID_RANGE_LOSSY_AV_END 199
/* Packets in this range can be used for anything. */
#define PACKET_ID_RANGE_LOSSY_CUSTOM_START 200
#define PACKET_ID_RANGE_LOSSY_CUSTOM_END 254
#define PACKET_ID_RANGE_LOSSY_END 254

/* Messages. */

#define PACKET_ID_PADDING 0 /* Denotes padding */
#define PACKET_ID_REQUEST 1 /* Used to request unreceived packets */
#define PACKET_ID_KILL    2 /* Used to kill connection */

#define PACKET_ID_ONLINE 24
#define PACKET_ID_OFFLINE 25
#define PACKET_ID_NICKNAME 48
#define PACKET_ID_STATUSMESSAGE 49
#define PACKET_ID_USERSTATUS 50
#define PACKET_ID_TYPING 51

/* TODO(oxij): Make a sub-range instead?
   But it's unclear what the sub-range end should be. 68? 79?
   WTF is MSI packet anyway? It has a callback and no users.
*/

#define PACKET_ID_MESSAGE 64
#define PACKET_ID_ACTION 65 /* PACKET_ID_MESSAGE + MESSAGE_ACTION */
#define PACKET_ID_MSI 69
#define PACKET_ID_FILE_SENDREQUEST 80
#define PACKET_ID_FILE_CONTROL 81
#define PACKET_ID_FILE_DATA 82
#define PACKET_ID_INVITE_CONFERENCE 96
#define PACKET_ID_ONLINE_PACKET 97
#define PACKET_ID_DIRECT_CONFERENCE 98
#define PACKET_ID_MESSAGE_CONFERENCE 99
#define PACKET_ID_LOSSY_CONFERENCE 199

#endif
