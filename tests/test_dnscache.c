// T031 headless suite: DATA-04 clamp/grace/chain/LRU semantics (fake clock)
#include "composite_dnscache.h"
#include <stdio.h>

static int failures = 0;
#define CHECK(c, n) if (c) { printf("PASS: %s\n", n); } else { printf("FAIL: %s\n", n); failures++; }

static BYTE addr4a[4] = {1, 2, 3, 4};
static BYTE addr4b[4] = {5, 6, 7, 8};
static BYTE addr6[16] = {0x20, 0x01};

int main(void) {
    DNS_ENTRY e;

    // 1. basic upsert + lookup
    _app_dnscache_upsert(L"example.com", addr4a, FALSE, 300, 1000);
    CHECK(_app_dnscache_lookup(L"example.com", 1000, &e) && !e.stale, "fresh entry lookup");
    CHECK(e.expires_at == 1300, "ttl 300 respected within clamp band");

    // 2. TTL clamp floor: 5s -> 17s
    _app_dnscache_upsert(L"floor.com", addr4a, FALSE, 5, 1000);
    CHECK(_app_dnscache_lookup(L"floor.com", 1000, &e) && e.expires_at == 1017, "ttl floor clamp 17s");

    // 3. TTL clamp ceiling: 999999s -> 86400s
    _app_dnscache_upsert(L"ceil.com", addr4a, FALSE, 999999, 1000);
    CHECK(_app_dnscache_lookup(L"ceil.com", 1000, &e) && e.expires_at == 1000 + 86400, "ttl ceiling clamp 86400s");

    // 4. expiry + stale grace: expires 1017; at 1050 stale; at 1100 gone
    CHECK(_app_dnscache_lookup(L"floor.com", 1017, &e) && !e.stale, "at-expiry still fresh");
    CHECK(_app_dnscache_lookup(L"floor.com", 1050, &e) && e.stale, "within 60s grace = stale flag");
    CHECK(!_app_dnscache_lookup(L"floor.com", 1100, &e), "past grace = hard expired");

    // 5. eviction sweep
    CHECK(_app_dnscache_evict(1100) >= 1, "evict sweep removes past-grace entries");

    // 6. CNAME chain: a.com -> b.com -> c.com (terminal), depth 8 cap
    // (distinct address so resolveip cannot hit an earlier test entry)
    static BYTE chain_addr[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    _app_dnscache_upsert(L"a.com", chain_addr, FALSE, 300, 2000);
    _app_dnscache_upsert(L"b.com", chain_addr, FALSE, 300, 2000);
    _app_dnscache_upsert(L"c.com", chain_addr, FALSE, 300, 2000);
    CHECK(_app_dnscache_linkcname(L"a.com", L"b.com", 2000), "cname link a->b");
    CHECK(_app_dnscache_linkcname(L"b.com", L"c.com", 2000), "cname link b->c");
    WCHAR dom[DNS_DOMAIN_MAX];
    CHECK(_app_dnscache_resolveip(chain_addr, FALSE, 2000, dom, RTL_NUMBER_OF(dom)) && wcscmp(dom, L"c.com") == 0, "resolveip walks chain a->b->c to terminal");

    // 7. IPv6 entry + reverse lookup
    _app_dnscache_upsert(L"v6.test", addr6, TRUE, 300, 2000);
    CHECK(_app_dnscache_resolveip(addr6, TRUE, 2000, dom, RTL_NUMBER_OF(dom)) && wcscmp(dom, L"v6.test") == 0, "AAAA reverse lookup");
    CHECK(!_app_dnscache_resolveip(addr6, FALSE, 2000, dom, RTL_NUMBER_OF(dom)), "v4 lookup does not match v6 entry");

    // 8. LRU eviction at capacity: fill 64k then one more evicts the LRU
    ULONG fill_start = 3000;
    for (ULONG i = 0; i < DNS_CACHE_CAPACITY; i++) {
        WCHAR name[64];
        swprintf(name, 64, L"fill%lu.test", i);
        _app_dnscache_upsert(name, addr4a, FALSE, 300, fill_start);
    }
    CHECK(_app_dnscache_count() == DNS_CACHE_CAPACITY, "capacity reached (64k)");
    // touch nothing; insert one more at a later clock -> LRU evicts entries[0] (fill0)
    _app_dnscache_upsert(L"newone.test", addr4b, FALSE, 300, fill_start + 400);
    DNS_ENTRY probe;
    CHECK(!_app_dnscache_lookup(L"fill0.test", fill_start + 400, &probe), "LRU evicted the never-touched oldest entry");
    CHECK(_app_dnscache_lookup(L"newone.test", fill_start + 400, &probe), "new entry present after eviction");

    // 9. overwrite updates address + resets expiry
    _app_dnscache_upsert(L"example.com", addr4b, FALSE, 100, 5000);
    CHECK(_app_dnscache_lookup(L"example.com", 5000, &e) && memcmp(e.addr, addr4b, 4) == 0 && !e.stale, "upsert overwrites address");

    printf(failures == 0 ? "ALL TESTS PASSED\n" : "FAILURES: %d\n", failures);
    return failures == 0 ? 0 : 1;
}
