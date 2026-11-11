#include "composite_dnscache.h"
#include <stdio.h>
int main(void) {
    static BYTE a4[4] = {1,2,3,4};
    _app_dnscache_upsert(L"a.com", a4, FALSE, 300, 2000);
    _app_dnscache_upsert(L"b.com", a4, FALSE, 300, 2000);
    _app_dnscache_upsert(L"c.com", a4, FALSE, 300, 2000);
    printf("linked a->b: %d\n", _app_dnscache_linkcname(L"a.com", L"b.com", 2000));
    printf("linked b->c: %d\n", _app_dnscache_linkcname(L"b.com", L"c.com", 2000));
    DNS_ENTRY e;
    if (_app_dnscache_lookup(L"a.com", 2000, &e)) wprintf(L"a: depth=%lu parent=%s\n", e.chain_depth, e.cname_parent);
    if (_app_dnscache_lookup(L"b.com", 2000, &e)) wprintf(L"b: depth=%lu parent=%s\n", e.chain_depth, e.cname_parent);
    WCHAR dom[DNS_DOMAIN_MAX];
    printf("resolve: %d\n", _app_dnscache_resolveip(a4, FALSE, 2000, dom, 256));
    wprintf(L"resolved=%s\n", dom);
    return 0;
}
