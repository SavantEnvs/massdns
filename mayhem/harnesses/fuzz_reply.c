// fuzz_reply: one DNS reply datagram (what massdns receives from a resolver over UDP, or the body
// of a TCP length-prefixed message) through the dns.h parse + print chain, the way main.c's do_read()
// consumes it for each output format: dns_parse_question, then dns_print_packet (-o F), and the
// record walk dns_parse_record_raw -> dns_name2str / dns_raw_names_eq / dns_raw_record_data2str
// (-o S uses put_quotes=true, -o J false).
#include "massdns_fuzz_common.h"
#include "dns.h"

static FILE *sink;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // A reply is at most 0xFFFF bytes: the TCP length prefix is 16 bits and the UDP
    // read buffer in main.c is bounded the same way.
    if (size > 0xFFFF)
        return -1;
    if (!sink)
        sink = fopen("/dev/null", "w");

    // Exact-size heap copy so ASan sees any read past the end of the datagram.
    uint8_t *buf = malloc(size ? size : 1);
    memcpy(buf, data, size);

    static dns_pkt_t packet;
    uint8_t *body = NULL;
    memset(&packet.head, 0, sizeof(packet.head));
    if (dns_parse_question(buf, size, &packet.head, &body)) {
        uint8_t *end = buf + size;

        // -o F (dig-style full output)
        dns_print_packet(sink, &packet, buf, size, body);

        // -o L / -o J question line
        fputs(dns_name2str(&packet.head.question.name), sink);
        fputs(dns_record_type2str((dns_record_type) packet.head.question.type), sink);
        fputs(dns_class2str((dns_class) packet.head.question.class), sink);
        fputs(dns_rcode2str((dns_rcode) packet.head.header.rcode), sink);

        // -o S / -o J record walk
        for (int quotes = 0; quotes < 2; quotes++) {
            dns_record_t rec;
            uint8_t *next = body;
            uint16_t index = 0;
            while (dns_parse_record_raw(buf, next, end, &next, &rec)) {
                fputs(dns_section2str(dns_get_section(index++, &packet.head.header)), sink);
                fputs(dns_name2str(&rec.name), sink);
                dns_raw_names_eq(&rec.name, &packet.head.question.name);
                fputs(dns_raw_record_data2str(&rec, buf, end, quotes != 0), sink);
            }
        }
    }
    free(buf);
    return 0;
}
