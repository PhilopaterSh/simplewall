#include "composite_zones.h"
#include <stdio.h>

int main(void) {
    static ZONE_SET z; memset(&z, 0, sizeof(z));
    _app_zones_insert(&z,0x0A000000,0x0A0000FF);
    _app_zones_insert(&z,0x0A000100,0x0A0001FF);
    printf("after two touching: count=%lu [0]=%08x-%08x\n", z.count, z.ranges[0].start, z.ranges[0].end);
    _app_zones_insert(&z,0x0B000000,0x0B0000FF);
    printf("after gap: count=%lu\n", z.count);
    printf("fill-gap ins(0A000200-0AFFFFFF): ret=%d count=%lu\n", _app_zones_insert(&z,0x0A000200,0x0AFFFFFF), z.count);
    for (ULONG i=0;i<z.count;i++) printf("  [%lu]=%08x-%08x\n", i, z.ranges[i].start, z.ranges[i].end);

    // /32 verdict regression
    static ZONE_SET z2; memset(&z2, 0, sizeof(z2));
    ULONG s,e; BOOLEAN v6;
    printf("parse bare 10.0.0.5: ret=%d s=%08x e=%08x\n", _app_zones_parsecidr(L"10.0.0.5",&s,&e,&v6), s, e);
    _app_zones_insert(&z2, s, e);
    printf("  verdict on %08x: %d\n", s, _app_zones_contains(&z2, s));
    return 0;
}
