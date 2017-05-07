#ifndef __QUERY_RECORDER_INC
#define __QUERY_RECORDER_INC
#include "hashmap.h"
#include "dns_parse.h"

struct __attribute__((__packed__)) dns_record {
    enum dns_record_type rtype;
    unsigned long data_len;
    unsigned char *data;
}

#endif
