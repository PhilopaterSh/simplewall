#include "composite_bypass.h"
#include <stdio.h>

static int failures = 0;
#define CHECK(c, n) if (c) { printf("PASS: %s\n", n); } else { printf("FAIL: %s\n", n); failures++; }

int main(void) {
    _app_bypass_seeddefaults();
    CHECK(_app_bypass_count() >= 8, "defaults seeded");

    // 1. known resolver traffic flagged
    CHECK(_app_bypass_isresolvertraffic(0x08080808, 53), "8.8.8.8:53 flagged");
    CHECK(_app_bypass_isresolvertraffic(0x08080808, 853), "8.8.8.8:853 flagged");
    CHECK(_app_bypass_isresolvertraffic(0x01010105, 53), "cloudflare range flagged");

    // 2. loopback exempt (owned resolver lives there)
    CHECK(!_app_bypass_isresolvertraffic(0x7F000001, 53), "loopback exempt");

    // 3. non-resolver ports on resolver IPs not flagged (port match)
    CHECK(!_app_bypass_isresolvertraffic(0x08080808, 443), "8.8.8.8:443 not DNS traffic");

    // 4. arbitrary IPs not flagged
    CHECK(!_app_bypass_isresolvertraffic(0x0A000001, 53), "internal IP not flagged");

    // 5. custom endpoint
    CHECK(_app_bypass_addendpoint(0xC0A80001, 0xC0A8000A, 0, L"local-resolvers"), "custom endpoint added");
    CHECK(_app_bypass_isresolvertraffic(0xC0A80005, 53), "custom range flagged (any port)");
    CHECK(_app_bypass_isresolvertraffic(0xC0A80005, 445), "custom range any-port flagged");

    // 6. rules-as-data emission
    WCHAR buf[4096];
    ULONG n = _app_bypass_emitpackrules(buf, RTL_NUMBER_OF(buf));
    CHECK(n == _app_bypass_count(), "rules emitted = endpoint count");
    CHECK(wcsstr(buf, L"\"address\": \"8.8.8.8\"") != NULL, "pack schema address present");
    CHECK(wcsstr(buf, L"\"protocol\": \"udp\"") != NULL, "udp protocol for 53");
    CHECK(wcsstr(buf, L"\"protocol\": \"tcp\"") != NULL, "tcp protocol for 853 (DoT)");
    CHECK(wcsstr(buf, L"\"direction\": \"out\"") != NULL, "direction present");

    printf(failures == 0 ? "ALL TESTS PASSED\n" : "FAILURES: %d\n", failures);
    return failures == 0 ? 0 : 1;
}
