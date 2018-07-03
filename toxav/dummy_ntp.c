/*
 * NTP formula implementation
 */

#include "dummy_ntp.h"

#include <stdlib.h>
#include <stdio.h>

int64_t dntp_calc_offset(uint32_t remote_tstart, uint32_t remote_tend,
                          uint32_t local_tstart, uint32_t local_tend)
{
    // output value is in milliseconds
    // accuracy:
    /* If the routes do not have a common nominal delay,
     * there will be a systematic bias of half the difference
     * between the forward and backward travel times
     */

    // see: https://en.wikipedia.org/wiki/Network_Time_Protocol
    /*
     * t0 .. local_tstart
     * t1 .. remote_tstart
     * t2 .. remote_tend
     * t3 .. local_tend
     */

    int64_t offset = (int64_t)(
                        ((int64_t)remote_tstart - (int64_t)local_tstart)
                      + ((int64_t)remote_tend - (int64_t)local_tend)
                      )
                      / 2;
    return offset;
}

uint32_t dntp_calc_roundtrip_delay(uint32_t remote_tstart, uint32_t remote_tend,
                          uint32_t local_tstart, uint32_t local_tend)
{
    // output value is in milliseconds
    
    // see: https://en.wikipedia.org/wiki/Network_Time_Protocol
    /*
     * t0 .. local_tstart
     * t1 .. remote_tstart
     * t2 .. remote_tend
     * t3 .. local_tend
     */
     
    uint32_t roundtrip_delay = (local_tend - local_tstart)
                                - (remote_tend - remote_tstart);
    return roundtrip_delay;
}


void unit_test()
{
    #include <time.h>
    
    printf("dummy_ntp:testing ...\n");
    
    uint64_t res1;
    uint32_t res2;
    uint32_t rs;
    uint32_t re;
    uint32_t ls;
    uint32_t le;
    uint32_t ls_r;
    uint16_t trip1_ms;
    uint16_t trip2_ms;

    const uint16_t step = 5;
    int64_t diff;
    int64_t lstart;
    int64_t rstart;

    srand(time(NULL));

    for(int j=0;j<10;j++)
    {
        // ---------------
        lstart = rand() % 9999999 + 10000;
        rstart = rand() % 9999999 + 10000;
        diff = rstart - lstart;
        trip1_ms = rand() % 210 + 4;
        trip2_ms = rand() % 210 + 4;
        // ---------------
        // printf("diff=%ld trip1=%d trip2=%d\n", diff, trip1_ms, trip2_ms);
        ls = lstart;
        ls_r = lstart + diff;
        rs = ls_r + trip1_ms;
        re = rs + step;
        le = ls + trip1_ms + step + trip2_ms;
        res1 = dntp_calc_offset(rs, re,
                              ls, le);
        printf("offset=%ld ms\n", res1);
        printf("ERROR=%ld ms\n", (res1 - diff));
        res2 = dntp_calc_roundtrip_delay(rs, re,
                              ls, le);
        printf("round trip=%d ms\n", res2);
    }
}


