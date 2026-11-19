// Shared prelude for the massdns harnesses. massdns is one translation unit (src/main.c) plus
// header-only modules with non-static definitions, so each harness includes the headers it
// exercises exactly once. Build with `-iquote src` (src/string.h would shadow libc's <string.h>).
#ifndef MASSDNS_FUZZ_COMMON_H
#define MASSDNS_FUZZ_COMMON_H
#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif
