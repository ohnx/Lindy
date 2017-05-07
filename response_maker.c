#include "response_maker.h"

void make_response_bytes_for_a(void *inptr, unsigned int ipaddr) {
    struct dns_answer_a *resp = (struct dns_answer_a *)inptr;
    resp->header.name = htons((unsigned short)0xc00c);
    resp->header.type = htons((unsigned short)DNS_RECORD_A);
    resp->header.class = htons((unsigned short)0x0001);
    resp->header.ttl = htonl(0x0000012b);
    resp->header.dlen = htons((unsigned short)0x0004);
    resp->address = htonl(ipaddr);
}

void make_response_bytes_for_aaaa(void *inptr, unsigned char *ipaddr) {
    struct dns_answer_aaaa *resp = (struct dns_answer_aaaa *)inptr;
    int i;
    
    resp->header.name = htons((unsigned short)0xc00c); // endian swapped already
    resp->header.type = htons((unsigned short)DNS_RECORD_AAAA); // endian swapped already
    resp->header.class = htons((unsigned short)0x0001); // endian swapped already
    resp->header.ttl = htonl(0x0000012b); // not sure how to endian swap
    resp->header.dlen = htons((unsigned short)0x0010); // endian swapped
    
    for (i = 0; i < 16; i++) {
        resp->address[i] = ipaddr[i]; // when copying byte-for-byte, no endian trickery needed
    }
}

void make_response_bytes_for_txt(void *inptr, unsigned char *text, unsigned short textlength) {
    struct dns_answer_txt *resp = (struct dns_answer_txt *)inptr;
    unsigned char *tmp;
    unsigned short i;
    
    resp->header.name = htons((unsigned short)0xc00c);
    resp->header.type = htons((unsigned short)DNS_RECORD_TXT);
    resp->header.class = htons((unsigned short)0x0001);
    resp->header.ttl = htonl(0x0000012b);
    resp->header.dlen = htons((unsigned short)textlength);
    
    tmp = (unsigned char *)(&(resp->datastart));
    
    while (textlength--)
        tmp[textlength] = text[textlength]; // when copying byte-for-byte, no endian trickery needed
}