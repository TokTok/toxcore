
#ifndef DUMMY_NTP_H
#define DUMMY_NTP_H

#include <stdbool.h>
#include <stdint.h>

/* NTP formula implementation */
int64_t dntp_calc_offset(uint32_t remote_tstart, uint32_t remote_tend,
                         uint32_t local_tstart, uint32_t local_tend);
uint32_t dntp_calc_roundtrip_delay(uint32_t remote_tstart, uint32_t remote_tend,
                                   uint32_t local_tstart, uint32_t local_tend);

#endif /* DUMMY_NTP_H */
