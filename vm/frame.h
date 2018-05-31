#include <hash.h>
#include "threads/synch.h"
#include "vm/page.h"

#ifndef FRAME_H
#define FRAME_H

/* freeing protocol: 1.swap_disk 2.frame_table 3.sup_table */

struct lock frame_lock;
struct hash frame_table;
struct pool frame_pool;
struct pool evict;

struct pool {
    struct lock lock;
    struct list pool;
};

/* can be combined with frame struct */
struct evict_info {
    uint32_t *phys_addr;
    struct list_elem elem;
};

struct frame {
    uint32_t *phys_addr;
    uint32_t *vir_addr;
    bool is_pinned;
    struct thread *thread;
    struct page *page;
    
    struct hash_elem elem;
};

struct pool_elem {
    struct frame *frame;
    struct list_elem elem;
};

void frame_init(void);

void *alloc_frame(void *kpage);

void free_frame(uint32_t *phys_addr);

void set_pin_frame(void *page, bool pin);

void release_frames(struct thread *thread);

struct frame *get_frame(uint32_t *phys_addr);

void update_evict(uint32_t *phys_addr);

void destroy_pool(void);

unsigned frame_hash(struct hash_elem *elem, void *aux);

bool frame_less_func(struct hash_elem *elem_1, struct hash_elem *elem_2, void *aux);

#endif
