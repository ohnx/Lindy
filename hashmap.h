#include <string.h>
#include <stdlib.h>

#ifndef __HASHMAP_INC
#define __HASHMAP_INC

typedef struct _hashmap_entry {
    char *key;
    void *value;
} hashmap_entry;

typedef struct _hashmap_entry_list {
    int vlen;
    int vroom;
    hashmap_entry *values;
} hashmap_entry_list;

typedef struct _hashmap {
    hashmap_entry_list *buckets;
} hashmap;

typedef int (*hashmap_iterator)(void *context, const char *key, void *value);

hashmap *hashmap_new();
void hashmap_put(hashmap *in, const char *key, void *value);
void *hashmap_get(hashmap *in, const char *key);
int hashmap_iterate(hashmap *in, hashmap_iterator iter, void *context);
void hashmap_empty(hashmap *in);
void hashmap_destroy(hashmap *in);
#endif
