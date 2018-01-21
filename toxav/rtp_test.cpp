#include "rtp.h"

#include "../toxcore/crypto_core.h"

#include <byteswap.h>
#include <gtest/gtest.h>

// Reference implementation.
static void rtp_header_pack_ref(uint8_t *rdata, struct RTPHeader const *header)
{
    struct RTPHeader hton_header = *header;
    hton_header.sequnum = net_htons(hton_header.sequnum);
    hton_header.timestamp = net_htonl(hton_header.timestamp);
    hton_header.ssrc = net_htonl(hton_header.ssrc);
    hton_header.flags = bswap_64(hton_header.flags);
    hton_header.offset_full = net_htonl(hton_header.offset_full);
    hton_header.data_length_full = net_htonl(hton_header.data_length_full);
    hton_header.received_length_full = net_htonl(hton_header.received_length_full);
    for (size_t i = 0; i < sizeof hton_header.csrc / sizeof hton_header.csrc[0]; i++) {
        hton_header.csrc[i] = net_htonl(hton_header.csrc[i]);
    }
    hton_header.offset_lower = net_htons(hton_header.offset_lower);
    hton_header.data_length_lower = net_htons(hton_header.data_length_lower);
    memcpy(rdata, &hton_header, sizeof(struct RTPHeader));
}

TEST(Rtp, Serialisation) {
    RTPHeader header;
    random_bytes((uint8_t *)&header, sizeof header);

    uint8_t rdata[sizeof(RTPHeader)];
    rtp_header_pack(rdata, &header);

    uint8_t rdata_ref[sizeof(RTPHeader)];
    rtp_header_pack_ref(rdata_ref, &header);

    EXPECT_EQ(std::string((char const *)rdata, sizeof rdata),
              std::string((char const *)rdata_ref, sizeof rdata_ref));
}
