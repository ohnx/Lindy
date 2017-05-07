#ifndef __QUERY_RECORDS_INC
#define __QUERY_RECORDS_INC
#include "hashmap.h"
#include "dns_parse.h"

struct dns_record {
    enum dns_record_type rtype;
    unsigned long data_len;
    unsigned char *data;
};

struct dns_record get_record(hashmap *h, const char *name, enum dns_record_type rtype);
void add_record(hashmap *h, const char *name, struct dns_record rec);
#endif
