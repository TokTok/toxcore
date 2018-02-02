#include "rtp.h"

#include "../toxcore/crypto_core.h"

#include <gtest/gtest.h>

namespace
{
RTPHeader random_header()
{
    return {
        random_u16(),
        random_u16(),
        random_u16(),
        random_u16(),
        random_u16(),
        random_u16(),
        random_u16(),
        random_u32(),
        random_u32(),
        random_u64(),
        random_u32(),
        random_u32(),
        random_u32(),
        random_u16(),
        random_u16(),
    };
}
}  // namespace

TEST(Rtp, Deserialisation)
{
    RTPHeader const header = random_header();

    uint8_t rdata[sizeof(RTPHeader)];
    EXPECT_EQ(rtp_header_pack(rdata, &header), RTP_HEADER_SIZE);

    RTPHeader unpacked = {0};
    EXPECT_EQ(rtp_header_unpack(rdata, &unpacked), RTP_HEADER_SIZE);

    EXPECT_EQ(header.protocol_version, unpacked.protocol_version);
    EXPECT_EQ(header.pe, unpacked.pe);
    EXPECT_EQ(header.xe, unpacked.xe);
    EXPECT_EQ(header.cc, unpacked.cc);
    EXPECT_EQ(header.ma, unpacked.ma);
    EXPECT_EQ(header.pt, unpacked.pt);
    EXPECT_EQ(header.sequnum, unpacked.sequnum);
    EXPECT_EQ(header.timestamp, unpacked.timestamp);
    EXPECT_EQ(header.ssrc, unpacked.ssrc);
    EXPECT_EQ(header.flags, unpacked.flags);
    EXPECT_EQ(header.offset_full, unpacked.offset_full);
    EXPECT_EQ(header.data_length_full, unpacked.data_length_full);
    EXPECT_EQ(header.received_length_full, unpacked.received_length_full);
    EXPECT_EQ(header.offset_lower, unpacked.offset_lower);
    EXPECT_EQ(header.data_length_lower, unpacked.data_length_lower);
}
