#include "vm/frame.h"
#include <stdio.h>
#include "threads/synch.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include <string.h>
#include "threads/vaddr.h"

void frame_init(void)
{
    /* lock init */
    lock_init(&frame_pool.lock);
    lock_init(&frame_lock);
    list_init(&frame_pool.pool);
    lock_init(&evict.lock);
    list_init(&evict.list);
    
    /* Initialize Hash Table */
    hash_init(&frame_table, &frame_hash, &frame_less_func, NULL);
    
    /* Allocate all pages in the User Pool */
    void *kpage;
    while ((kpage = palloc_get_multiple(PAL_USER, 1)) != NULL)
    {
        struct frame *frame = (struct frame *) malloc(sizeof(struct frame));
        frame->phys_addr = kpage;
        frame->is_pinned = false;
        lock_acquire(&frame_pool.lock);
        list_push_front(&frame_pool.pool, &frame->elem);
        lock_release(&frame_pool.lock);
    }
}

/* implementing lazy load: have to deal with setting pagedir */
void *alloc_frame(void *kpage)
{
    struct frame *ret = NULL;
    lock_acquire(&frame_pool.lock);
    if (frame_pool.pool != NULL)
        ret = (struct frame *) list_pop_front(&frame_pool.pool);
    lock_release(&frame_pool.lock);
    if (ret != NULL)
    {
        ret->vir_addr = kpage->vir_addr;
        ret->thread = thread_current();
        ret->page = kpage;
        kpage->phys_addr = ret->phys_addr;
        kpage->phys_loc = in_memory;
        
        lock_acquire(&frame_lock);
        hash_insert(&frame_table, (hash_elem *) &ret->elem);
        lock_release(&frame_lock);
        
        struct evict_info *entry = (struct evict_info *) malloc(sizeof(struct evict_info));
        evict_info->phys_addr = ret->phys_addr;
        lock_acquire(&evict->lock);
        list_push_back(&evict->list, &entry->elem);
        lock_release(&evict->lock);
    }
    else
    {
        /* eviction protocol */
        struct list_elem *e;
        struct frame *f = NULL;
        lock_acquire(&evict->lock);
        for (e = list_begin(&evict->list); e != list_end(&evict->list); e = list_next(e))
        {
            struct evict_info *info = list_entry(e, struct evict_info, elem);
            
            if ((f = get_frame(info->phys_addr)) == NULL)
                return NULL;
            
            if (!f->is_pinned && f->page->page_t != EXEC)
            {
                info = (struct evict_info *) list_remove(&info->elem);
                break;
            }
        }
        lock_release(&evict->lock);
        free(info);
        
        lock_acquire(&f->thread->pgdir_lock);
        pagedir_clear_page (f->thread->pagedir, f->vir_addr);
        lock_release(&f->thread->pgdir_lock);
        
        ret = swap_out_frame(f);
        ret->vir_addr = kpage->vir_addr;
        ret->thread = thread_current();
        ret->page = kpage;
        kpage->phys_addr = ret->phys_addr;
    }
    return ret;
}

/* does not remove entry in thread sup_table */
/* what if want to release frame and it's in swap disk */
/* does not clear pagedir */
void free_frame(uint32_t *phys_addr)
{
    struct frame frame;
    frame.phys_addr = phys_addr;

    lock_acquire(&frame_lock);
    struct hash_elem *entry;
    if ((entry = hash_find(&frame_table, &frame.elem)) != NULL)
    {
        frame = hash_entry(entry, struct frame, elem);
        hash_delete(&frame_table, &frame->elem);
    }
    lock_release(&frame_lock);

    if (entry != NULL)
    {
        if (frame.page->page_loc == in_memory) {
            struct list_elem *e;
            lock_acquire(&evict->lock);
            for (e = list_begin(&evict->list); e != list_end(&evict->list); e = list_next(e))
            {
                struct evict_info *f = list_entry(e, struct evict_info, elem);
                if (f->phys_addr == frame.phys_addr)
                {
                    f = (struct evict_info *) list_remove(&f->elem);
                    free(f);
                    break;
                }
            }
            lock_release(&evict->lock);
            
            memset(&frame + sizeof(uint32_t *), 0, PGSIZE - sizeof(uint32_t *));
            
            lock_acquire(&frame_pool.lock);
            list_push_front(&frame_pool.pool, frame.elem);
            lock_release(&frame_pool.lock);
        }

        else if (frame.page->page_loc == swap_disk)
        {
            free_sect(frame.page->swap_index);
        }
    }
    return;
}

/* release all frames in frame table then destroy thread sup_table */
void release_frames(struct thread *thread) 
{
    struct hash_iterator i;
    
    hash_first(&i, &thread->sup_table);
    while(hash_next(&i))
    {
        struct page *f = hash_entry(hash_cur(&i), struct page, elem);
        free_frame(f->phys_addr);
    }
    return;
}

void set_pin_frame(void *page, bool pin)
{
    struct frame *frame = get_frame(page->phys_addr);
    if (frame == NULL)
        return;
    else
        frame->is_pinned = pin;
    return;
}

struct frame *get_frame(uint32_t *phys_addr)
{
    struct hash_elem result;
    struct frame entry;
    
    entry.phys_addr = phys_addr;
    result = hash_find(&frame_table, &entry.elem);
    return hash_entry (result, struct frame, elem);
}

void update_evict(uint32_t *phys_addr)
{
    struct list_elem *e;
    lock_acquire(&evict->lock);
    for (e = list_begin(&evict->list); e != list_end(&evict->list); e = list_next(e))
    {
        struct evict_info *f = list_entry(e, struct evict_info, elem);
        if (f->phys_addr == phys_addr)
        {
            f = list_remove(&f->elem);
            list_push_back(&evict->list, &f->elem);
            break;
        }
    }
    lock_release(&evict->lock);
}

unsigned frame_hash(struct hash_elem *hash_elemt, void *aux)
{
    struct frame *frame = (struct frame *) hash_entry(hash_elemt, struct frame, elem);
    return hash_bytes(&frame->phys_addr, sizeof(frame->phys_addr));
}

bool frame_less_func(struct hash_elem *elem_1, struct hash_elem *elem_2, void *aux)
{
    struct frame *frame_1 = (struct frame *) hash_entry(elem_1, struct frame, elem);
    struct frame *frame_2 = (struct frame *) hash_entry(elem_2, struct frame, elem);
    
    return (frame_1->phys_addr < frame_2->phys_addr);
}
