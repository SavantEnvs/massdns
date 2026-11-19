// fuzz_addr: resolver / bind address strings — each line of the resolvers file (-r), the -b/--bind
// argument and the per-line dedicated resolvers of --extended-input all go through net.h's
// str_to_addr(), after main.c's trim_end(); accepted addresses are printed back with sockaddr2str()
// (as massdns does in its output and log lines). Input is newline-separated lines.
#include "massdns_fuzz_common.h"
#include "string.h"
#include "massdns.h" // pulls net.h with the types/epoll headers it needs, as main.c does

static FILE *sink;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!sink)
        sink = fopen("/dev/null", "w");

    char line[4096];
    size_t i = 0;
    while (i < size) {
        size_t n = 0;
        while (i < size && n < sizeof(line) - 1) {
            char c = (char) data[i++];
            line[n++] = c;
            if (c == '\n')
                break;
        }
        line[n] = 0;
        trim_end(line);
        // resolvers file uses default port 53; -b uses 0.
        for (int k = 0; k < 2; k++) {
            char copy[4096];
            memcpy(copy, line, n + 1);
            struct sockaddr_storage addr;
            memset(&addr, 0, sizeof(addr));
            if (str_to_addr(copy, k ? 0 : 53, &addr))
                fputs(sockaddr2str(&addr), sink);
        }
    }
    return 0;
}
