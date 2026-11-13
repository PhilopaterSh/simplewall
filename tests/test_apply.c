// headless tests for the FR-11 diff core
#include "composite_apply.h"
#include <stdio.h>

static int failures = 0;
#define CHECK(c, n) if (c) { printf("PASS: %s\n", n); } else { printf("FAIL: %s\n", n); failures++; }

static GUID mk(int i) { GUID g = { (ULONG)i, 0x1111, 0x2222, {0} }; return g; }

int main(void) {
    GUID live[8], desired[8];
    APP_APPLY_DIFF d;

    // identical sets -> empty delta (the NFR-04 fast path)
    for (int i = 0; i < 4; i++) { live[i] = mk(i); desired[i] = mk(i); }
    _app_apply_diff(live, 4, desired, 4, &d);
    CHECK(d.adds_count == 0 && d.removes_count == 0 && !d.overflow, "identical sets = zero delta");

    // add 1: desired has mk(4) extra
    for (int i = 0; i < 4; i++) { live[i] = mk(i); desired[i] = mk(i); }
    desired[4] = mk(4);
    _app_apply_diff(live, 4, desired, 5, &d);
    GUID exp4 = mk(4);
    CHECK(d.adds_count == 1 && IsEqualGUID(&d.adds[0], &exp4) && d.removes_count == 0, "one add detected");

    // remove 1: live has mk(2) that desired dropped
    for (int i = 0; i < 4; i++) { live[i] = mk(i); desired[i] = mk(i); }
    desired[2] = mk(9);
    _app_apply_diff(live, 4, desired, 4, &d);
    GUID exp2 = mk(2);
    CHECK(d.adds_count == 1 && d.removes_count == 1 && IsEqualGUID(&d.removes[0], &exp2), "one remove + one add (swap)");

    // overflow: delta exceeds APP_APPLY_MAX
    {
        static GUID l[APP_APPLY_MAX + 4], ds[4];
        for (ULONG i = 0; i < APP_APPLY_MAX + 4; i++) l[i] = mk((int)(i % 0x1000) + 1000 + (int)i);
        for (int i = 0; i < 4; i++) ds[i] = mk(i);
        _app_apply_diff(l, APP_APPLY_MAX + 4, ds, 4, &d);
        CHECK(d.overflow, "overflow flagged -> caller falls back to full rebuild");
    }

    printf(failures == 0 ? "ALL TESTS PASSED\n" : "FAILURES: %d\n", failures);
    return failures == 0 ? 0 : 1;
}
