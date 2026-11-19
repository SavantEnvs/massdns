// fuzz_name_line: the domain-list input file massdns reads (one query per line, optionally
// prefixed by a record type, e.g. "MX example.com" or "PTR 1.2.3.4"). Each line goes through the
// same steps as main.c's next_query() + new_lookup() + send_query(): trim_end, record-type token
// via dns_str_to_record_type, trim_start, then dns_ip2ptr (PTR) or dns_str2namebuf, and
// dns_question_create_from_name. The built query is then parsed back with dns_parse_question and
// printed with dns_name2str, as a resolver echoing the question would make massdns do.
#include "massdns_fuzz_common.h"
#include "string.h"
#include "dns.h"

static FILE *sink;

static void one_line(char *line)
{
    trim_end(line);

    dns_record_type rtype = DNS_REC_A;
    char *name = line;
    size_t rtype_len = strcspn(line, "\t ");
    char orig_delim = line[rtype_len];
    line[rtype_len] = 0;
    dns_record_type qtype = dns_str_to_record_type(line);
    line[rtype_len] = orig_delim;
    if (qtype != DNS_REC_INVALID) {
        name = trim_start(line + rtype_len);
        rtype = qtype;
        if (*name == 0)
            return;
    }

    dns_name_t qname;
    memset(&qname, 0, sizeof(qname));
    if (rtype != DNS_REC_PTR || !dns_ip2ptr(name, &qname)) {
        ssize_t len = dns_str2namebuf(name, qname.name);
        if (len < 0)
            return; // "Illegal DNS name" in new_lookup()
        qname.length = (uint8_t) len;
    }

    // main.c builds the query into its 0x20000-byte packet_buffer; the question is
    // 12 header bytes + name (< 0x100) + 4, so an exact-size heap buffer is enough.
    size_t qsize = dns_question_size(&qname);
    uint8_t *query = malloc(qsize);
    uint16_t qlen = dns_question_create_from_name(query, &qname, rtype, 0x1234);
    dns_buf_set_rd(query, true);

    dns_head_t head;
    uint8_t *body;
    if (dns_parse_question(query, qlen, &head, &body)) {
        fputs(dns_name2str(&head.question.name), sink);
        fputs(dns_record_type2str((dns_record_type) head.question.type), sink);
        dns_names_eq(&head.question.name, &qname);
    }
    free(query);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!sink)
        sink = fopen("/dev/null", "w");

    // Split like fgets(line, 4096, file): lines are cut at '\n' or after 4095 bytes. An
    // embedded NUL ends the C string, exactly as it would for fgets' caller.
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
        one_line(line);
    }
    return 0;
}
