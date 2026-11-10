#include "composite_zones.h"
#include <stdio.h>
int main(void) {
    static ZONE_SET big; memset(&big, 0, sizeof(big));
    ULONG fails = 0;
    for (ULONG i = 0; i < 2 * 1024 * 1024; i++) {
        ULONG net = i * 512;
        if (!_app_zones_insert(&big, net, net | 0xFF)) { printf("insert refused at i=%lu (count=%lu)\n", i, big.count); fails++; break; }
    }
    printf("count=%lu expected=%lu\n", big.count, 2*1024*1024);
    ULONG ip = (1024u * 512) | 0x7F;
    printf("verdict in-range ip=%08x -> %d\n", ip, _app_zones_contains(&big, ip));
    ip = (1024u * 512) | 0x100;
    printf("verdict gap-past ip=%08x -> %d\n", ip, _app_zones_contains(&big, ip));
    ip = (1024u * 512) - 1;
    printf("verdict gap-before ip=%08x -> %d\n", ip, _app_zones_contains(&big, ip));
    return 0;
}
