#include "query_records.h"

static struct dns_record rec_nf = { DNS_RECORD_UNKNOWN, 0, NULL };
struct dns_record_arr {
    int len;
    struct dns_record *arr;
};

struct dns_record get_record(hashmap *h, const char *name, enum dns_record_type rtype) {
    struct dns_record_arr *record_array;
    int i;
    
    record_array = (struct dns_record_arr *)hashmap_get(h, name);
    if (!record_array) {
        /* try removing the dot if there was one, or adding it if there wasn't */
        char *temp;
        int len;
        len = strlen(name);
        if (name[len - 1] == '.') { /* check if last character is a dot */
            temp = malloc(len); /* allocate memory for everything up to the dot + null */
            strncpy(temp, name, len - 1);
            temp[len - 1] = '\0';
        } else { /* last character is not a dot so we check if we add one */
            temp = malloc(len + 2); /* allocate memory for everything up to the dot + the dot + null */
            strncpy(temp, name, len);
            temp[len] = '.';
            temp[len+1] = '\0';
        }
        record_array = (struct dns_record_arr *)hashmap_get(h, temp);
        free(temp);
        
        /* check if with the dot / without dot there is a result domain yet */
        if (!record_array) return rec_nf; /* domain not found */
    }
    
    /* search for the query type */
    for (i = record_array->len - 1; i >= 0; i--) {
        if (record_array->arr[i].rtype == rtype) return record_array->arr[i]; /* return if found */
    }
    
    return rec_nf; /* type not found */
}

void add_record(hashmap *h, const char *name, struct dns_record rec) {
    struct dns_record_arr *record_array;
    int index;
    
    record_array = (struct dns_record_arr *)hashmap_get(h, name);
    
    if (!record_array) {
        /* new one */
        record_array = malloc(sizeof(struct dns_record_arr));
        record_array->len = 1;
        record_array->arr = malloc(sizeof(struct dns_record));
        
        /* insert into hashmap */
        hashmap_put(h, name, record_array);
        index = 0;
    } else {
        index = record_array->len;
        /* increase size of array */
        record_array->arr = realloc(record_array->arr, sizeof(struct dns_record) * (++(record_array->len)));
    }
    
    ((record_array->arr)[index]).rtype = rec.rtype;
    ((record_array->arr)[index]).data_len = rec.data_len;
    ((record_array->arr)[index]).data = rec.data;
}

