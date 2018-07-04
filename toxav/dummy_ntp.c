/*
 * NTP formula implementation
 */

#include "dummy_ntp.h"

#include <stdlib.h>
#include <stdio.h>

#define DRIFT_PERCENTAGE    15

bool dntp_drift(int64_t *current_offset, const int64_t new_offset, const int64_t max_offset_for_drift)
{
    bool did_jump = false;

    if (current_offset == NULL)
    {
        // HINT: input param is NULL
        return did_jump;
    }

    if (abs(new_offset - *current_offset) > max_offset_for_drift)
    {
        // HINT: jump
        *current_offset = new_offset;
        did_jump = true;
    }
    else
    {
        // HINT: drift
        int64_t delta = (new_offset - *current_offset) * DRIFT_PERCENTAGE;
        *current_offset = *current_offset + (int64_t)(delta / 100.0f);
    }

    return did_jump;
}

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

#if UNIT_TESTING_ENABLED

void unit_test()
{
    #ifndef __MINGW32__
    #include <time.h>
    #endif
    
    printf("dummy_ntp:testing ...\n");
    
    int64_t res1;
    uint32_t res2;
    bool res3;
    uint32_t rs;
    uint32_t re;
    uint32_t ls;
    uint32_t le;
    uint32_t ls_r;
    uint16_t trip1_ms;
    uint16_t trip2_ms;
    int64_t current_offset;

    const uint16_t step = 5;
    int64_t diff;
    int64_t lstart;
    int64_t rstart;

    #ifndef __MINGW32__
    srand(time(NULL));
    #else
    // TODO: fixme ---
    srand(localtime());
    // TODO: fixme ---
    #endif

    current_offset = 0;

    for(int j=0;j<10;j++)
    {
        // ---------------
        lstart = rand() % 9999999 + 10000;
        rstart = lstart + (rand() % 100);
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
        printf("offset=%lld ms\n", res1);
        printf("ERROR=%lld ms\n", (res1 - diff));
        res2 = dntp_calc_roundtrip_delay(rs, re,
                              ls, le);
        printf("round trip=%ld ms\n", res2);

        printf("current_offset=%lld offset=%lld ms\n", current_offset, res1);
        res3 = dntp_drift(&current_offset, res1, 50);
        printf("current_offset new=%lld ms bool res=%d\n", current_offset, (int)res3);
    }

}

#endif
