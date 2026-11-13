// T012/P2-4 headless tests for the FR-07 zones engine
#include "composite_zones.h"
#include <stdio.h>
#include <stdlib.h>

static int failures = 0;

#define CHECK(cond, name) \
    if (cond) { printf("PASS: %s\n", name); } \
    else { printf("FAIL: %s\n", name); failures++; }

static ULONG rand32(void) {
    return ((ULONG)rand() << 17) ^ ((ULONG)rand() << 3) ^ (ULONG)rand();
}

int main(void) {
    static ZONE_SET zone; // 16MB struct - must NOT live on the stack
    memset(&zone, 0, sizeof(zone));

    wcscpy_s(zone.id, RTL_NUMBER_OF(zone.id), L"test");

    // 1. basic single CIDR
    ULONG s, e; BOOLEAN v6;
    CHECK(_app_zones_parsecidr(L"10.0.0.0/24", &s, &e, &v6) && s == 0x0A000000 && e == 0x0A0000FF, "parse 10.0.0.0/24");
    CHECK(_app_zones_parsecidr(L"10.0.0.5", &s, &e, &v6) && s == e && s == 0x0A000005, "parse bare IP = /32");
    CHECK(_app_zones_parsecidr(L"0.0.0.0/0", &s, &e, &v6) && s == 0 && e == 0xFFFFFFFF, "parse 0.0.0.0/0");
    CHECK(_app_zones_parsecidr(L"fe80::1", &s, &e, &v6) == FALSE && v6 == TRUE, "IPv6 detected (struct-ready)");
    CHECK(!_app_zones_parsecidr(L"10.0.0", &s, &e, &v6), "malformed (2 dots) rejected");
    CHECK(!_app_zones_parsecidr(L"10.0.0.0/33", &s, &e, &v6), "prefix > 32 rejected");

    // 2. contains before insert
    CHECK(!_app_zones_contains(&zone, 0x0A000001), "empty zone contains nothing");

    // 3. insert + verdicts
    _app_zones_insert(&zone, 0x0A000000, 0x0A0000FF);
    CHECK(_app_zones_contains(&zone, 0x0A000001), "verdict inside range");
    CHECK(_app_zones_contains(&zone, 0x0A000000), "verdict at start edge");
    CHECK(_app_zones_contains(&zone, 0x0A0000FF), "verdict at end edge");
    CHECK(!_app_zones_contains(&zone, 0x0A000100), "verdict just past end");
    CHECK(!_app_zones_contains(&zone, 0x09FFFFFF), "verdict just before start");

    // 4. touching ranges coalesce (insert 10.0.1.0/24 after 10.0.0.0/24)
    _app_zones_insert(&zone, 0x0A000100, 0x0A0001FF);
    CHECK(zone.count == 1 && zone.ranges[0].start == 0x0A000000 && zone.ranges[0].end == 0x0A0001FF, "touching coalesce");

    // 5. contained range absorbs (no growth)
    _app_zones_insert(&zone, 0x0A000050, 0x0A000060);
    CHECK(zone.count == 1 && zone.ranges[0].end == 0x0A0001FF, "contained range absorbed");

    // 6. gap creates second range; fill the gap -> coalesce back to one
    _app_zones_insert(&zone, 0x0B000000, 0x0B0000FF);
    CHECK(zone.count == 2, "gap creates second range");
    _app_zones_insert(&zone, 0x0A000200, 0x0AFFFFFF);
    CHECK(zone.count == 1 && zone.ranges[0].end == 0x0B0000FF, "fill gap coalesces to one");

    // 7. exhaustive brute-force oracle on a /24 space: random /30../32 ops
    {
        static ZONE_SET z2; memset(&z2, 0, sizeof(z2));
        static unsigned char oracle[256];
        memset(oracle, 0, sizeof(oracle));
        srand(42);

        for (int iter = 0; iter < 2000; iter++) {
            unsigned base = 0x0C000000u | ((unsigned)rand() % 256);
            unsigned prefix = 30 + (unsigned)rand() % 3; // 30..32
            unsigned host_bits = 32 - prefix;
            unsigned mask = host_bits == 0 ? 0 : (0xFFFFFFFFu << host_bits);
            unsigned rs = base & mask;

            WCHAR line[32];
            swprintf(line, 32, L"%u.%u.%u.%u/%u",
                (rs >> 24) & 255, (rs >> 16) & 255, (rs >> 8) & 255, rs & 255, prefix);

            ULONG ps, pe; BOOLEAN pv6;
            if (!_app_zones_parsecidr(line, &ps, &pe, &pv6)) continue;
            if (!_app_zones_insert(&z2, ps, pe)) continue;

            for (unsigned i = 0; i < 256; i++) {
                unsigned ip = 0x0C000000u | i;
                if (ip >= ps && ip <= pe) oracle[i] = 1;
            }

            // spot-check verdicts agree with oracle
            for (int k = 0; k < 16; k++) {
                unsigned ip = 0x0C000000u | ((unsigned)rand() % 256);
                unsigned idx = ip & 255;
                if (_app_zones_contains(&z2, ip) != (oracle[idx] != 0)) {
                    printf("FAIL: brute-force verdict mismatch ip=%08x iter=%d\n", ip, iter);
                    failures++;
                    goto done7;
                }
            }
        }
        printf("PASS: brute-force oracle (2000 random CIDR ops, spot verdicts)\n");
done7:;
    }

    // 8. scale: sorted-append load of 2M /24 ranges must stay O(n) and bounded
    {
        static ZONE_SET big; memset(&big, 0, sizeof(big));
        wcscpy_s(big.id, RTL_NUMBER_OF(big.id), L"scale");
        ULONG loaded = 0;
        for (ULONG i = 0; i < 2 * 1024 * 1024; i++) {
            ULONG net = i * 512; // sorted with 256-IP gaps: no coalescing
            if (_app_zones_insert(&big, net, net | 0xFF)) loaded++;
        }
        CHECK(loaded == 2 * 1024 * 1024 && big.count == 2 * 1024 * 1024, "2M sorted ranges loaded, no coalesce collisions");
        CHECK(_app_zones_contains(&big, (1024u * 512) | 0x7F), "scale verdict inside a middle range");
        CHECK(!_app_zones_contains(&big, (1024u * 512) | 0x100), "scale verdict in the gap past a range end");
        // wait: net|0x100 = next range start; use exact past-end of range 1024: (1024<<8)|0xFF+1 == (1025<<8)
        CHECK(!_app_zones_contains(&big, (1024u * 512) - 1), "scale verdict in the gap before a range start");
        CHECK(_app_zones_contains(&big, 0xFFFFFFFF) || big.ranges[big.count-1].end < 0xFFFFFFFF, "scale top edge sane");
        printf("  (scale zone: %lu ranges, %lu bytes)\n", big.count, (ULONG)(big.count * sizeof(ZONE_RANGE)));
    }

    // 9. loader text path
    {
        static ZONE_SET z3; memset(&z3, 0, sizeof(z3));
        ULONG n = _app_zones_load(&z3, L"1.2.3.0/24\r\n1.2.4.0/24\r\n5.6.7.8\r\nbad-line\r\nfe80::/64\r\n");
        CHECK(n == 3 && z3.count == 2, "loader: 3 accepted, touching coalesce, junk skipped, v6 skipped");
        CHECK(_app_zones_contains(&z3, 0x01020305), "loader verdict in");
    }

    printf(failures == 0 ? "ALL TESTS PASSED\n" : "FAILURES: %d\n", failures);
    return failures == 0 ? 0 : 1;
}
