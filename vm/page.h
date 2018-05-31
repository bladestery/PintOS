#include <stdbool.h>
#include <stdlib.h>
#include "filesys/file.h"
#include "threads/vaddr.h"
#include <hash.h>

#ifndef PAGE_H
#define PAGE_H
enum page_loc_t {
    not_loaded = 0,
    in_memory = 1,
    swap_disk = 2
    };

enum page_type {/* do we need this? */
    DEF = 0,
    FILE = 1,
    EXEC = 2,
    SWAP = 3,
    ZERO = 4
    };

struct page {
    uint32_t *phys_addr;
    uint32_t *vir_addr;
    
    enum page_loc_t page_loc;
    enum page_type page_t;
    
    struct file *file;
    off_t offset;
    uint32_t read_bytes;
    uint32_t zero_bytes;
    bool writable;
    
    size_t swap_index;
    
    struct hash_elem hash_elem;
};

struct page *create_page(struct file *file, off_t offset, uint32_t read_bytes, uint32_t zero_bytes, bool writable, uint32_t *vir_addr);

struct page *get_page(void *vir_addr);

void add_page(struct page *kpage);

void release_pages(struct hash* hash);

unsigned page_hash(struct hash_elem *elem, void *aux);

bool page_less_func(struct hash_elem *elem_1, struct hash_elem *elem_2, void *aux);

#endif
