#include <types.h>
#include <memory.h>
#include <mmap.h>
#include <fork.h>
#include <v2p.h>
#include <page.h>

#define MAX_LENGTH 2097152

/* 
 * You may define macros and other helper functions here
 * You must not declare and use any static/global variables 
 * */
#define PAGE_SIZE 4096
#define ROUND_UP(x) (((x) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))  // ~ INVERTS THE BITS. PAGE_SIZE-1 = 12 ones in binary

#define PGD_INDEX(va) (((va) >> 39) & 0x1FF)
#define PUD_INDEX(va) (((va) >> 30) & 0x1FF)
#define PMD_INDEX(va) (((va) >> 21) & 0x1FF)
#define PTE_INDEX(va) (((va) >> 12) & 0x1FF)
#define PAGE_OFFSET(va) ((va) & 0xFFF)

// #define PTE_PRESENT 0x1
// #define PTE_WRITE   0x4
// #define PTE_USER    0x8

// from enum in memory.h
#define OS_PT_REG 1
#define USER_REG 2

// Function to check if can merge 2 nodes
int can_merge(struct vm_area *a, struct vm_area *b) {
    return (a && b && a->access_flags == b->access_flags && a->vm_end == b->vm_start);
}

// Function to merge new node with previous and next node
void merge_adjacent(struct exec_context *current,struct vm_area *prev, struct vm_area *curr, struct vm_area *new_node) {
    //Merge with previous node if possible
    if (prev != current->vm_area && can_merge(prev, new_node)) {
        prev->vm_end = new_node->vm_end;
        prev->vm_next = new_node->vm_next;
        os_free(new_node, sizeof(struct vm_area));
        stats->num_vm_area--;
        if(can_merge(prev, curr)) {
            prev->vm_end = curr->vm_end;
            prev->vm_next = curr->vm_next;
            os_free(curr, sizeof(struct vm_area));
            stats->num_vm_area--;
        }
    }
    // Merge with next node if possible
    else if (can_merge(new_node, curr)) {
        new_node->vm_end = curr->vm_end;
        new_node->vm_next = curr->vm_next;
        os_free(curr, sizeof(struct vm_area));
        stats->num_vm_area--;
    }
}

struct vm_area *create_vma(long start, long end, int prot)
{
    struct vm_area *new_vma = os_alloc(sizeof(struct vm_area));
    new_vma->vm_start = start;
    new_vma->vm_end = end;
    new_vma->access_flags = prot;
    stats->num_vm_area += 1;
    return new_vma;
}

// Function to change protection in page table
void update_protection(u64 start, u64 end, int prot) 
{
    for (u64 addr = start; addr < end; addr += 4096) 
    {
        struct exec_context *ctx = get_current_ctx();
        u64 pgd_pfn = ctx->pgd;

        // pgd
        u64 *pgd = (u64 *)osmap(pgd_pfn);
        u64 pgd_index = (addr >> 39) & 0x1FF;
        if (!(pgd[pgd_index] & 0x1)) continue;
        u64 pud_pfn = pgd[pgd_index] >> 12;

        // pud
        u64 *pud = (u64 *)osmap(pud_pfn);
        u64 pud_index = (addr >> 30) & 0x1FF;
        if (!(pud[pud_index] & 0x1)) continue;
        u64 pmd_pfn = pud[pud_index] >> 12;

        // pmd
        u64 *pmd = (u64 *)osmap(pmd_pfn);
        u64 pmd_index = (addr >> 21) & 0x1FF;
        if (!(pmd[pmd_index] & 0x1)) continue;
        u64 pte_pfn = pmd[pmd_index] >> 12;

        // pte
        u64 *pte = (u64 *)osmap(pte_pfn);
        u64 pte_index = (addr >> 12) & 0x1FF;
        if (!(pte[pte_index] & 0x1)) continue;

        u64 pfn = pte[pte_index] >> 12;

        //case where page is present
        if (!(pte[pte_index] & 0x1))
            return;

        // case where page is shared
        if (get_pfn_refcount(pfn) != 1) {
            if (prot == PROT_READ) {
                pte[pte_index] &= ~0x8; 
            }

        //case where page is private
        } else {
            if ((prot & PROT_WRITE) == PROT_WRITE)
                pte[pte_index] |= 0x8;   
            else
                pte[pte_index] &= ~0x8;  
        }

        //Flushing TLB entry
        asm volatile("invlpg (%0)" ::"r"(addr) : "memory");
    }
}


// Function to create new vm_area node
struct vm_area* create_node(struct vm_area *prev, struct vm_area *curr, unsigned long start, int length, int prot) {
    struct vm_area *new_node = os_alloc(sizeof(struct vm_area));
    if (!new_node) return NULL;

    new_node->vm_start = start;
    new_node->vm_end = start + length;
    new_node->access_flags = prot;
    new_node->vm_next = curr;

    prev->vm_next = new_node;
    stats->num_vm_area++;
    return new_node;
}

int max(int a, int b) {
    return (a > b) ? a : b;
}
int min(int a, int b) {
    return (a < b) ? a : b;
}

long vm_area_mprotect(struct exec_context *current, u64 addr, int length, int prot)
{
    if(current == NULL || length < 0 || length > MAX_LENGTH || addr >= MMAP_AREA_END || addr < MMAP_AREA_START || prot <= 0 || prot >= 4)
        return -1;

    if (length == 0)
        return 0;

    if(length % 4096 != 0)
        length = ROUND_UP(length);
    

    if(current->vm_area == NULL){
        current->vm_area = create_vma(MMAP_AREA_START, MMAP_AREA_START + 4096, 0);
        current->vm_area->vm_next = NULL;
        stats->num_vm_area = 1;
    }

    u64 end_addr = addr + length;
    struct vm_area *prev = current->vm_area;
    struct vm_area *curr = prev->vm_next;
    int modified = 0;

    while (curr != NULL)
    {
        // Case where regions are non overlapping
        if (curr->vm_end <= addr || curr->vm_start >= end_addr)
        {
            prev = curr;
            curr = curr->vm_next;
            continue;
        }
        
        // Casee where region has the updated permissions
        if (curr->access_flags == prot)
        {
            prev = curr;
            curr = curr->vm_next;
            continue;
        }
        
        modified = 1;
        
        // Case where current region contains the entire range
        if (curr->vm_start < addr && curr->vm_end > end_addr)
        {            
            struct vm_area *middle = create_vma(addr, end_addr, prot);
            struct vm_area *last = create_vma(end_addr, curr->vm_end, curr->access_flags);
            
            curr->vm_end = addr;
 
            middle->vm_next = last;
            last->vm_next = curr->vm_next;
            curr->vm_next = middle;
            
            // Updates protection for middle region
            update_protection(addr, end_addr, prot);
            break;
        }
        // Case where current region overlaps with the start of the range
        else if (curr->vm_start < addr && curr->vm_end > addr && curr->vm_end <= end_addr)
        {
            // Split the region into two parts
            // First part: from original start to addr with original permission(curr)
            // Second part: from addr to original end with new permissions
            
            struct vm_area *second = create_vma(addr, curr->vm_end, prot);
            second->vm_next = curr->vm_next;
            
            curr->vm_end = addr;
            curr->vm_next = second;
            
            // Updates protection for second region
            update_protection(addr, second->vm_end, prot);
            prev = second;
            curr = second->vm_next;
        }

        // Case where current region overlaps with the end of the range
        else if (curr->vm_start >= addr && curr->vm_start < end_addr && curr->vm_end > end_addr)
        {
            // Split the region into two parts
            // First part: from current start to end_addr with new permissions(curr)
            // Second part: from end_addr to original end with original permissions
            
            struct vm_area *second = create_vma(end_addr, curr->vm_end, curr->access_flags);
            second->vm_next = curr->vm_next;
            
            curr->vm_end = end_addr;
            curr->access_flags = prot;
            curr->vm_next = second;
            
            // Update protection for curr region
            update_protection(curr->vm_start, end_addr, prot);
            break;
        }

        // Case where current region is completely contained within requested range
        else if (curr->vm_start >= addr && curr->vm_end <= end_addr)
        {
            curr->access_flags = prot;
            
            // Update protection 
            update_protection(curr->vm_start, curr->vm_end, prot);
            
            // Merges with prev regions if possible
            if (prev != current->vm_area && prev->access_flags == prot && prev->vm_end == curr->vm_start)
            {
                prev->vm_end = curr->vm_end;
                prev->vm_next = curr->vm_next;
                os_free(curr, sizeof(struct vm_area));
                stats->num_vm_area--;
                
                curr = prev->vm_next;
            }
            else
            {
                prev = curr;
                curr = curr->vm_next;
            }
        }
    }
    
    // Check if merging is possible with next region
    prev = current->vm_area;
    curr = prev->vm_next;
    
    while (curr != NULL && curr->vm_next != NULL)
    {
        if (curr->access_flags == curr->vm_next->access_flags &&
            curr->vm_end == curr->vm_next->vm_start)
        {
            struct vm_area *next = curr->vm_next;
            curr->vm_end = next->vm_end;
            curr->vm_next = next->vm_next;
            os_free(next, sizeof(struct vm_area));
            stats->num_vm_area--;
        }
        else
        {
            prev = curr;
            curr = curr->vm_next;
        }
    }
    
    return modified ? 0 : -EINVAL;
}

/**
 * mmap system call implementation.
 */
long vm_area_map(struct exec_context *current, u64 addr, int length, int prot, int flags)
{
    // Check if valid input
    if (length <= 0 || length > 2*1024*1024 || !(prot == PROT_READ || prot == (PROT_READ | PROT_WRITE)) || (flags != 0 && flags != MAP_FIXED))
        return -1;
    if(current->vm_area == NULL){
        struct vm_area *dummy = os_alloc(sizeof(struct vm_area));
        dummy->vm_start = MMAP_AREA_START;
        dummy->vm_end = MMAP_AREA_START + PAGE_SIZE;
        dummy->access_flags = 0;
        dummy->vm_next = NULL;
        current->vm_area = dummy;
        stats->num_vm_area++;
    }

    // Given in assignment to return -1 if addr is 0 and flags is MAP_FIXED
    if(addr == 0 && flags == MAP_FIXED)
        return -1;

    length = ROUND_UP(length);

    // Implementing functionality for addr == 0
    if(addr == 0){
        struct vm_area *prev = current->vm_area;
        struct vm_area *curr = prev->vm_next;

        while(curr != NULL){
            unsigned long start = prev->vm_end;
            unsigned long end = curr->vm_start;

            if(end - start >= length){
                struct vm_area *new_node = create_node(prev, curr, start, length, prot);
                if (!new_node) return -1;
                unsigned long temp = new_node->vm_start;
                merge_adjacent(current, prev, curr, new_node);

                return temp;
            }
            prev = curr;
            curr = curr->vm_next;
        }

        // Check if there is space at the end of the list
        if(MMAP_AREA_END - prev->vm_end >= length){
            struct vm_area *new_node = create_node(prev, curr, prev->vm_end, length, prot);
            if (!new_node) return -1;
            unsigned long temp = new_node->vm_start;
            merge_adjacent(current, prev, curr, new_node);

            return temp;
        }


        // No space available
        return -1;
    }

    // Implementing functionality for addr != 0
    else{
        if(addr < MMAP_AREA_START || addr + length > MMAP_AREA_END)
            return -1;
        struct vm_area *prev = current->vm_area;
        struct vm_area *curr = prev->vm_next;

        // Flag is MAP_FIXED
        if(flags == MAP_FIXED){
            while(curr != NULL && curr->vm_start <= addr){
                prev = curr;
                curr = curr->vm_next;
            }

            if((prev != current->vm_area && addr < prev->vm_end) || (curr != NULL && addr + length > curr->vm_start)){
                return -1;
            }
            if(MMAP_AREA_END - prev->vm_end < length)
                return -1;

            struct vm_area *new_node = create_node(prev, curr, addr, length, prot);
            if (!new_node) return -1;
            unsigned long temp = new_node->vm_start;
            merge_adjacent(current, prev, curr, new_node);

            return temp;
        }
        // Flag is 0
        else{
            // Check if we can insert at given address
            struct vm_area *prev = current->vm_area;
            struct vm_area *curr = prev->vm_next;

            while(curr != NULL && curr->vm_start <= addr){
                prev = curr;
                curr = curr->vm_next;
            }

            if(prev->vm_end <= addr && (curr == NULL || addr + length <= curr->vm_start)){
                struct vm_area *new_node = create_node(prev, curr, addr, length, prot);
                if (!new_node) return -1;
                unsigned long temp = new_node->vm_start;
                merge_adjacent(current, prev, curr, new_node);

                return temp;
            }

            // If inserting at given address is not possible, we will try to find a free space
            prev = current->vm_area;
            curr = prev->vm_next;

            while(curr != NULL){
                unsigned long start = prev->vm_end;
                unsigned long end = curr->vm_start;

                if(end - start >= length){
                    struct vm_area *new_node = create_node(prev, curr, start, length, prot);
                    if (!new_node) return -1;
                    unsigned long temp = new_node->vm_start;
                    merge_adjacent(current, prev, curr, new_node);

                    return temp;
                }
                prev = curr;
                curr = curr->vm_next;
            }

            // Check if there is space at the end of the list
            if(MMAP_AREA_END - prev->vm_end >= length){
                struct vm_area *new_node = create_node(prev, curr, prev->vm_end, length, prot);
                if (!new_node) return -1;
                unsigned long temp = new_node->vm_start;
                merge_adjacent(current, prev, curr, new_node);

                return temp;
            }
            // No space available
            return -1;
        }
    }
}

/**
 * munmap system call implemenations
 */
long vm_area_unmap(struct exec_context *current, u64 addr, int length)
{
    // Check if input is valid
    if (length <= 0 || current == NULL || addr < MMAP_AREA_START || addr >= MMAP_AREA_END || length > MAX_LENGTH)
    {
        return -1;
    }
    
    // Round up length
    length = ROUND_UP(length);
    
    u64 start = addr;
    u64 end = addr + length;
    
    // Initialize VM area if not already done
    if (current->vm_area == NULL)
    {
        current->vm_area = create_vma(MMAP_AREA_START, MMAP_AREA_START + PAGE_SIZE, 0);
        current->vm_area->vm_next = NULL;
        stats->num_vm_area = 1;
    }
    
    struct vm_area *prev = current->vm_area;
    struct vm_area *curr = prev->vm_next;
    int unmapped = 0;
    
    while (curr != NULL)
    {
        u64 s = curr->vm_start; 
        u64 e = curr->vm_end;
        
        // Skip non-overlapping regions
        if (e <= start || s >= end)
        {
            prev = curr;
            curr = curr->vm_next;
            continue;
        }
        
        // Free pages in the overlapping region
        for (u64 va = max(start, s); va < min(end, e); va += PAGE_SIZE)
        {
            u64 *pgd = (u64 *)osmap(current->pgd);
            u64 pgd_idx = (va >> 39) & 0x1FF;
            
            if (!(pgd[pgd_idx] & 0x1)) {
                continue;  // PGD entry not present
            }
            
            u64 *pud = (u64 *)osmap(pgd[pgd_idx] >> 12);
            u64 pud_idx = (va >> 30) & 0x1FF;
            
            if (!(pud[pud_idx] & 0x1)) {
                continue;  // PUD entry not present
            }
            
            u64 *pmd = (u64 *)osmap(pud[pud_idx] >> 12);
            u64 pmd_idx = (va >> 21) & 0x1FF;
            
            if (!(pmd[pmd_idx] & 0x1)) {
                continue;  // PMD entry not present
            }
            
            u64 *pte = (u64 *)osmap(pmd[pmd_idx] >> 12);
            u64 pte_idx = (va >> 12) & 0x1FF;
            
            if (!(pte[pte_idx] & 0x1)) {
                continue;  // PTE entry not present
            }
            
            // Get the PFN
            u64 pfn = pte[pte_idx] >> 12;
            
            // Check reference count
            if (get_pfn_refcount(pfn) != 1) {
                // Page is shared
                put_pfn(pfn);
            }
            else {
                // Page is unique
                put_pfn(pfn);
                os_pfn_free(USER_REG, pfn);
            }
            
            pte[pte_idx] = 0;
            
            // Flush this entry from TLB as we changed permissions
            asm volatile("invlpg (%0)" ::"r"(va) : "memory");
        }
        
        unmapped = 1;
        
        // Case 1: Unmap region is in the middle of current VM area
        if (s < start && e > end)
        {
            // Split into two parts
            struct vm_area *new = os_alloc(sizeof(struct vm_area));
            if (!new) return -ENOMEM;
            
            new->vm_start = end;
            new->vm_end = e;
            new->access_flags = curr->access_flags;
            new->vm_next = curr->vm_next;
            
            curr->vm_end = start;
            curr->vm_next = new;
            
            stats->num_vm_area++;
            break;
        }
        // Case 2: Current VM area completely inside unmap region
        else if (s >= start && e <= end)
        {
            // Remove current VM area
            prev->vm_next = curr->vm_next;
            os_free(curr, sizeof(struct vm_area));
            stats->num_vm_area--;
            curr = prev->vm_next;
            continue;
        }
        // Case 3: Unmap overlaps with end of VM area
        else if (s < start && e <= end)
        {
            curr->vm_end = start;
        }
        // Case 4: Unmap overlaps with start of VM area
        else if (s >= start && e > end)
        {
            curr->vm_start = end;
        }
        
        prev = curr;
        curr = curr->vm_next;
    }
    
    return unmapped ? 0 : -1;
}


long vm_area_pagefault(struct exec_context *current, u64 addr, int error_code)
{
    // check if input is valid
    if(addr < MMAP_AREA_START || addr >= MMAP_AREA_END || current == NULL)
        return -1;
    
    if(error_code != 6 && error_code != 7 && error_code != 4)
        return -1;
    
    // Initialize vm_area if it doesn't exist
    if(current->vm_area == NULL) {
        current->vm_area = create_vma(MMAP_AREA_START, MMAP_AREA_START + 4096, 0);
        current->vm_area->vm_next = NULL;
        stats->num_vm_area = 1;
    }
    
    // Find corresponding vm_area
    struct vm_area *curr = current->vm_area->vm_next;
    while(curr != NULL) {
        if(curr->vm_start <= addr && addr < curr->vm_end)
            break;
        curr = curr->vm_next;
    }

    if(curr == NULL)
        return -1;
    
    // Handle CoW fault (error code 7 = present + write + user)
    if(error_code == 7) {
        if((curr->access_flags & PROT_WRITE) == PROT_WRITE) {
            handle_cow_fault(current, addr, curr->access_flags);
            return 1;
        }
        else {
            return -1;
        }
    }
    // Check for read access violation (error code 6 = present + !write + user)
    else {
        if(curr->access_flags == PROT_READ && error_code == 6) {
            return -1;
        }

        u64 *pgd = (u64 *)osmap(current->pgd);
        u64 *pud, *pmd, *pte;
        
        // PGD
        if(!(pgd[PGD_INDEX(addr)] & 0x1)) {  
            u32 pfn = os_pfn_alloc(OS_PT_REG);
            if(pfn == 0) return -1;
            pgd[PGD_INDEX(addr)] = (pfn << 12) | (1 << 4) | (1 << 3) | 0x1;  // U+W+P
        }
        
        // PUD
        pud = (u64 *)osmap(pgd[PGD_INDEX(addr)] >> 12);
        if(!(pud[PUD_INDEX(addr)] & 0x1)) {  
            u32 pfn = os_pfn_alloc(OS_PT_REG);
            if(pfn == 0) return -1;
            pud[PUD_INDEX(addr)] = (pfn << 12) | (1 << 4) | (1 << 3) | 0x1;  // U+W+P
        }
        
        // PMD
        pmd = (u64 *)osmap(pud[PUD_INDEX(addr)] >> 12);
        if(!(pmd[PMD_INDEX(addr)] & 0x1)) {  
            u32 pfn = os_pfn_alloc(OS_PT_REG);
            if(pfn == 0) return -1;
            pmd[PMD_INDEX(addr)] = (pfn << 12) | (1 << 4) | (1 << 3) | 0x1;  // U+W+P
        }
        
        // PTE
        pte = (u64 *)osmap(pmd[PMD_INDEX(addr)] >> 12);
        if(!(pte[PTE_INDEX(addr)] & 0x1)) {  
            int write_flag = 0;
            if((curr->access_flags & PROT_WRITE) == PROT_WRITE)
                write_flag = 1;
                
            u32 pfn = os_pfn_alloc(USER_REG);
            if(pfn == 0) return -1;
            
            // Create PTE with correct permissions
            pte[PTE_INDEX(addr)] = (pfn << 12) | (1 << 4) | (write_flag << 3) | 0x1;  // U+W?+P
        }
        
        return 1;
    }
}


int memory_copy(long begin, long end, long pgd_old, long pgd_new)
{
    begin = begin - begin % 4096;

    long *rt_ptr_old = osmap(pgd_old);
    long *rt_ptr_new = osmap(pgd_new);

    for (long addr = begin; addr < end; addr += 4096)
    {
        // PGD
        int offset = (addr >> 39) % 512;  
        if (rt_ptr_old[offset] % 2 == 0) {
            rt_ptr_new[offset] = 0;
            continue;
        }
        
        if (rt_ptr_new[offset] % 2 == 0) {
            long temp = os_pfn_alloc(OS_PT_REG);
            if (temp == 0) {
                return -1;
            }
            rt_ptr_new[offset] = (temp << 12) + (rt_ptr_old[offset] % 4096);
        }
        
        // PUD
        long *pud_old = osmap(rt_ptr_old[offset] >> 12);
        long *pud_new = osmap(rt_ptr_new[offset] >> 12);
        
        offset = (addr >> 30) % 512;
        if (pud_old[offset] % 2 == 0) {
            pud_new[offset] = 0;
            continue;
        }
        
        if (pud_new[offset] % 2 == 0) {
            long temp = os_pfn_alloc(OS_PT_REG);
            if (temp == 0) {
                return -1;
            }
            pud_new[offset] = (temp << 12) + (pud_old[offset] % 4096);
        }
        
        // PMD
        long *pmd_old = osmap(pud_old[offset] >> 12);
        long *pmd_new = osmap(pud_new[offset] >> 12);
        
        offset = (addr >> 21) % 512;
        if (pmd_old[offset] % 2 == 0) {
            pmd_new[offset] = 0;
            continue;
        }

        if (pmd_new[offset] % 2 == 0) {
            long temp = os_pfn_alloc(OS_PT_REG);
            if (temp == 0) {
                return -1;
            }
            pmd_new[offset] = (temp << 12) + (pmd_old[offset] % 4096);
        }
        
        // PTE
        long *pte_old = osmap(pmd_old[offset] >> 12);
        long *pte_new = osmap(pmd_new[offset] >> 12);
        
        offset = (addr >> 12) % 512;
        
        if (pte_old[offset] % 2 != 0) {
            // Clear write permission bit (bit 3) from the source page
            pte_old[offset] = pte_old[offset] & (-9);
            
            pte_new[offset] = pte_old[offset];
            
            // Increment reference count for the physical page
            get_pfn(pte_old[offset] >> 12);
            
            // Flush this entry from TLB as we changed permissions
            asm volatile("invlpg (%0)" ::"r"(addr) : "memory");
        } 
        else {
            // If page is not present in source, mark it as not present in destination
            pte_new[offset] = 0;
        }
    }
    
    return 0;
}

/**
 * cfork system call implemenations
 * The parent returns the pid of child process. The return path of
 * the child process is handled separately through the calls at the 
 * end of this function (e.g., setup_child_context etc.)
 */

long do_cfork()
{
    u32 pid;
     struct exec_context *new_ctx = get_new_ctx();
     struct exec_context *ctx = get_current_ctx();
//     /*
//      * Must not modify above this line
//      */
        new_ctx->ppid = ctx->pid;
        new_ctx->type = ctx->type;
        new_ctx->state = ctx->state;
        new_ctx->used_mem = ctx->used_mem;

        new_ctx->pgd = os_pfn_alloc(OS_PT_REG);
        if (new_ctx->pgd == 0) return -1;
        //new_ctx->os_rsp = ctx->os_rsp;
        new_ctx->regs = ctx->regs;

        for(int i = 0; i < MAX_MM_SEGS; i++) {
            new_ctx->mms[i] = ctx->mms[i];
        }
        
        if(ctx->vm_area == NULL)
            new_ctx->vm_area = NULL;
        else {
            new_ctx->vm_area = create_vma(MMAP_AREA_START, MMAP_AREA_START + 4096, 0);
            struct vm_area *prev = new_ctx->vm_area;
            struct vm_area *curr = ctx->vm_area->vm_next;
            while(curr != NULL) {
                struct vm_area *new_node = create_vma(curr->vm_start, curr->vm_end, curr->access_flags);
                if (!new_node) return -1;
                new_node->vm_next = NULL;

                prev->vm_next = new_node;
                prev = new_node;
                stats->num_vm_area++;
                
                curr = curr->vm_next;
            }
        }

        for(int i = 0; i < CNAME_MAX; i++) {
            new_ctx->name[i] = ctx->name[i];
        }

        new_ctx->pending_signal_bitmap = ctx->pending_signal_bitmap;

        for(int i = 0; i < MAX_SIGNALS; i++) {
            new_ctx->sighandlers[i] = ctx->sighandlers[i];
        }

        new_ctx->ticks_to_sleep = ctx->ticks_to_sleep;
        new_ctx->alarm_config_time = ctx->alarm_config_time;
        new_ctx->ticks_to_alarm = ctx->ticks_to_alarm;

        for(int i = 0; i < MAX_OPEN_FILES; i++) {
            new_ctx->files[i] = ctx->files[i];
        }

        new_ctx->ctx_threads = ctx->ctx_threads;

        // Copy CODE, RODATA, and DATA segments
        for (int i = 0; i < 3; i++) {
            if (memory_copy(ctx->mms[i].start, ctx->mms[i].next_free, ctx->pgd, new_ctx->pgd) == -1) {
                return -1;
            }
        }

        // Duplicate STACK segment
        if (memory_copy(ctx->mms[MM_SEG_STACK].start, ctx->mms[MM_SEG_STACK].end, ctx->pgd, new_ctx->pgd) == -1) {
            return -1;
        }

        // Duplicate all VMAs
        if (ctx->vm_area != NULL) {
            for (struct vm_area *vma = ctx->vm_area->vm_next; vma != NULL; vma = vma->vm_next) {
                if (memory_copy(vma->vm_start, vma->vm_end, ctx->pgd, new_ctx->pgd) == -1) {
                    return -1;
                }
            }
        }
        
        


//     /*
//      * Must not modify below this line
//      */
    copy_os_pts(ctx->pgd, new_ctx->pgd);
    do_file_fork(new_ctx);
    setup_child_context(new_ctx);
    return pid;
}

// /* Cow fault handling, for the entire user address space
//  * For address belonging to memory segments (i.e., stack, data) 
//  * it is called when there is a CoW violation in these areas. 
//  *
//  * For vm areas, your fault handler 'vm_area_pagefault'
//  * should invoke this function
//  * */

long handle_cow_fault(struct exec_context *current, u64 vaddr, int access_flags)
{
    if(current == NULL)
        return -1;
    
    u64 *pgd = (u64 *)osmap(current->pgd);
    u64 *pud, *pmd, *pte;
    
    // PGD level
    if(!(pgd[PGD_INDEX(vaddr)] & 0x1)) 
        return -1;
    
    // PUD level
    pud = (u64 *)osmap(pgd[PGD_INDEX(vaddr)] >> 12);
    if(!(pud[PUD_INDEX(vaddr)] & 0x1))
        return -1;
    
    // PMD level
    pmd = (u64 *)osmap(pud[PUD_INDEX(vaddr)] >> 12);
    if(!(pmd[PMD_INDEX(vaddr)] & 0x1))
        return -1;
    
    // PTE level
    pte = (u64 *)osmap(pmd[PMD_INDEX(vaddr)] >> 12);
    if(!(pte[PTE_INDEX(vaddr)] & 0x1))
        return -1;
    
    long pte_val = pte[PTE_INDEX(vaddr)];
    long old_pfn = pte_val >> 12;
    
    // Check the reference count of the physical page
    int refcount = get_pfn_refcount(old_pfn);
    
    if(refcount <= 1) {
        // Page is not shared
        pte[PTE_INDEX(vaddr)] = pte_val | 0x8; // Make writable bit 1 (bit 3)
    }

    else {
        // Page is shared, need to create a private copy
        long new_pfn = os_pfn_alloc(USER_REG);
        if(new_pfn == 0) {
            // Allocation failed
            return -1;
        }
        
        // Copy info from old to new page
        long *old_page = osmap(old_pfn);
        long *new_page = osmap(new_pfn);
        for(int i = 0; i < 512; i++) {
            new_page[i] = old_page[i];
        }
        
        // Update PTE but use old flags
        pte[PTE_INDEX(vaddr)] = (new_pfn << 12) | (pte_val & 0xFFF);
        
        // Make writable bit 1
        pte[PTE_INDEX(vaddr)] |= 0x8;
        
        // Decrease the reference count of the old page
        put_pfn(old_pfn);
    }
    
    // Flush this entry from TLB as we changed permissions
    asm volatile("invlpg (%0)" ::"r"(vaddr) : "memory");
    
    return 1;
}