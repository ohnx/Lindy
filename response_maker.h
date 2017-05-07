#ifndef __RESPONSE_MAKER_INC
#define __RESPONSE_MAKER_INC
#include <netinet/in.h>
#include <arpa/inet.h>
#include "dns_parse.h"

struct __attribute__((__packed__)) dns_answer_a {
    struct dns_answer header;
    unsigned int address;
};
void make_response_bytes_for_a(void *inptr, unsigned int ipaddr);

struct __attribute__((__packed__)) dns_answer_aaaa {
    struct dns_answer header;
    unsigned char address[16];
};
void make_response_bytes_for_aaaa(void *inptr, unsigned char *ipaddr);

struct __attribute__((__packed__)) dns_answer_txt {
    struct dns_answer header;
    unsigned char datastart;
};
void make_response_bytes_for_txt(void *inptr, unsigned char *text, unsigned short textlength);

#endif
