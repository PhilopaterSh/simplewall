// T034 headless suite: wire build/parse (fake responses) + live DoH query
#include "composite_doh.h"
#include "composite_dnscache.h"
#include <stdio.h>
#include <time.h>

static int failures = 0;
#define CHECK(c, n) if (c) { printf("PASS: %s\n", n); } else { printf("FAIL: %s\n", n); failures++; }

int main(void) {
    BYTE q[512], resp[512], addrs[DOH_MAX_ADDRS * 16];
    ULONG qlen, ttl = 0, count;

    // 1. query build: header + name + qtype/qclass
    qlen = _app_doh_buildquery(L"example.com", 1, q, sizeof(q));
    CHECK(qlen > 0, "query built");
    CHECK(q[2] == 0x01 && q[3] == 0x00 && q[5] == 1, "header: RD=1, qdcount=1");
    // name labels: 7"example"5"com"0 -> offset 12+13=25, then qtype=1 qclass=1
    CHECK(qlen == 29, "query length = 12 + 13 + 4");
    CHECK(q[12] == 7 && memcmp(&q[13], "example", 7) == 0, "first label 'example'");

    // 2. parse a hand-built response: header + question echo + one A answer
    ULONG msg = 0;
    resp[msg++] = 0; resp[msg++] = 0; resp[msg++] = 0x81; resp[msg++] = 0x80; // QR+RD+RA
    resp[msg++] = 0; resp[msg++] = 1; resp[msg++] = 0; resp[msg++] = 1; resp[msg++] = 0; resp[msg++] = 0; resp[msg++] = 0; resp[msg++] = 0;
    resp[msg++] = 7; memcpy(&resp[msg], "example", 7); msg += 7;
    resp[msg++] = 3; memcpy(&resp[msg], "com", 3); msg += 3;
    resp[msg++] = 0;
    resp[msg++] = 0; resp[msg++] = 1; resp[msg++] = 0; resp[msg++] = 1; // A/IN
    // answer: name ptr 0xc00c, type A, class IN, ttl 120, rdlen 4, rdata
    resp[msg++] = 0xC0; resp[msg++] = 0x0C;
    resp[msg++] = 0; resp[msg++] = 1; resp[msg++] = 0; resp[msg++] = 1;
    resp[msg++] = 0; resp[msg++] = 0; resp[msg++] = 0; resp[msg++] = 120;
    resp[msg++] = 0; resp[msg++] = 4;
    resp[msg++] = 93; resp[msg++] = 184; resp[msg++] = 216; resp[msg++] = 34;
    count = _app_doh_parseanswers(resp, msg, 1, addrs, DOH_MAX_ADDRS, &ttl);
    CHECK(count == 1 && addrs[0] == 93 && addrs[3] == 34 && ttl == 120, "A answer parsed (ptr compression + ttl)");

    // 3. malformed: truncated answer rejected
    CHECK(_app_doh_parseanswers(resp, 20, 1, addrs, DOH_MAX_ADDRS, &ttl) == 0, "truncated response rejected");

    // 4. cached via upsert inside live path? (offline: verify cache missed)
    DNS_ENTRY e;
    CHECK(!_app_dnscache_lookup(L"example.com", 1, &e), "cache empty before live query");

    // 5. LIVE DoH query against Cloudflare (network required)
    BOOLEAN is_v6 = FALSE;
    BOOLEAN ok = _app_doh_query(L"example.com", 1, L"cloudflare-dns.com", addrs, &is_v6, &ttl);
    CHECK(ok && ttl > 0, "LIVE DoH query (cloudflare-dns.com, A example.com)");
    if (ok) printf("  resolved: %u.%u.%u.%u ttl=%lus\n", addrs[0], addrs[1], addrs[2], addrs[3], ttl);
    CHECK(_app_dnscache_lookup(L"example.com", (ULONG)time(NULL), &e) && !e.stale, "live answer auto-cached (DATA-04 clamps)");

    printf(failures == 0 ? "ALL TESTS PASSED\n" : "FAILURES: %d\n", failures);
    return failures == 0 ? 0 : 1;
}
