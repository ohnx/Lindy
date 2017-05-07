#include "hashmap.h"

#define TOPBIT (1 << 7)
#define POLYNOMIAL 0x9b
#define HMSIZE 256

static unsigned char table8[256];
static int tinit = 0;

void crc8_init() {
    int dividend;
    unsigned char bit, remainder;
    
    tinit = 1;
    
    /*
     * Compute the remainder of each possible dividend.
     */
    for (dividend = 0; dividend < 256; dividend++) {
        /*
         * Start with the dividend followed by zeros.
         */
        remainder = dividend;

        /*
         * Perform modulo-2 division, a bit at a time.
         */
        for (bit = 8; bit > 0; --bit) {
            /*
             * Try to divide the current data bit.
             */
            if (remainder & TOPBIT) {
                remainder = (remainder << 1) ^ POLYNOMIAL;
            } else {
                remainder = (remainder << 1);
            }
        }

        /*
         * Store the result into the table.
         */
        table8[dividend] = remainder;
    }
}

unsigned char crc8_block(const unsigned char *bytes, long byteLen) {
    long rpos = 0;
    unsigned char remainder = 0, data;
    
    /*
     * Divide the message by the polynomial, a byte at a time.
     */
    for (rpos = 0; rpos < byteLen; ++rpos) {
        data = bytes[rpos] ^ remainder;
        remainder = table8[data] ^ (remainder << 8);
    }

    /*
     * The final remainder is the CRC.
     */
    return remainder;
}

hashmap *hashmap_new() {
    hashmap *ret;
    hashmap_entry_list *buckets;

    if (!tinit) crc8_init();

    /* clear initial values */
    ret = calloc(1, sizeof(hashmap));
    buckets = calloc(HMSIZE, sizeof(hashmap_entry));
    
    if (ret == NULL || buckets == NULL) return NULL;
    
    ret->buckets = buckets;
    return ret;
}

void hashmap_put(hashmap *in, const char *key, void *value) {
    unsigned char crc8;
    hashmap_entry_list *hel;
    hashmap_entry *he;
    
    /* get hash value */
    crc8 = crc8_block((const unsigned char *)key, (long)strlen(key));
    hel = &in->buckets[crc8];
    
    /* reallocate memory if necessary */
    if (hel->vroom < ++(hel->vlen)) {
        hel->vroom = (hel->vroom == 0 ? 4 : hel->vroom*2);
        he = realloc(hel->values, hel->vroom * sizeof(hashmap_entry));

        if (he == NULL) {
            return; /* TODO: Throw exception */
        }
        
        hel->values = he;
    }
    
    /* jump to end of hashmap entry list */
    he = &hel->values[hel->vlen-1];
    
    he->key = strdup(key);
    he->value = value;
    
    /* success */
}

void *hashmap_get(hashmap *in, const char *key) {
    unsigned char crc8;
    hashmap_entry_list *hel;
    hashmap_entry *he;
    int i;
    
    /* get hash value */
    crc8 = crc8_block((const unsigned char *)key, (long)strlen(key));
    hel = &in->buckets[crc8];
    
    /* loop through all the key/value pairs with that hash */
    for (i = 0; i < hel->vlen; i++) {
        he = &hel->values[i];
        if (!strcmp(key, he->key)) goto found; /* found exact key */
    }
    return NULL;
    
    /* success */
    found:
    return he->value;
}

int hashmap_iterate(hashmap *in, hashmap_iterator iter, void *context) {
    hashmap_entry_list *hel;
    hashmap_entry *he;
    int i, j;
    
    /* loop through all the buckets */
    for (i = 0; i < HMSIZE; i++) {
        hel = &in->buckets[i];

        /* loop through all the key/value pairs */
        for (j = 0; j < hel->vlen; j++) {
            he = &hel->values[j];
            
            /* call the function */
            if (iter(context, he->key, he->value))
                return -1;
        }
    }
    
    return 0;
}

void hashmap_empty(hashmap *in) {
    hashmap_entry_list *hel;
    hashmap_entry *he;
    int i, j;
    
    /* loop through all the buckets */
    for (i = 0; i < HMSIZE; i++) {
        hel = &in->buckets[i];
        
        /* loop through all the key/value pairs */
        for (j = 0; j < hel->vlen; j++) {
            he = &hel->values[j];
            
            /* free the key */
            free(he->key);
        }
        
        /* reset the key/value pairs array */
        free(hel->values);
        hel->values = NULL;
        hel->vlen = 0;
        hel->vroom = 0;
    }
}

void hashmap_destroy(hashmap *in) {
    /* empty hashmap */
    hashmap_empty(in);
    
    /* clean up bucket storage */
    free(in->buckets);
    free(in);
}
