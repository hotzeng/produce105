/* Author(s): <Your name here>
 * COS 318, Fall 2015: Project 5 Virtual Memory
 * Implementation of the memory manager for the kernel.
*/

/* memory.c
 *
 * Note: 
 * There is no separate swap area. When a data page is swapped out, 
 * it is stored in the location it was loaded from in the process' 
 * image. This means it's impossible to start two processes from the 
 * same image without screwing up the running. It also means the 
 * disk image is read once. And that we cannot use the program disk.
 *
 */

#include "common.h"
#include "kernel.h"
#include "scheduler.h"
#include "memory.h"
#include "thread.h"
#include "util.h"
#include "interrupt.h"
#include "tlb.h"
#include "usb/scsi.h"

#define SECTOR_SIZE 512

/* Static global variables */
// Keep track of all pages: their vaddr, status, and other properties
static page_map_entry_t page_map[PAGEABLE_PAGES];

// address of the kernel page directory (shared by all kernel threads)
static uint32_t *kernel_pdir;

// allocate the kernel page tables
static uint32_t *kernel_ptabs[N_KERNEL_PTS];

//other global variables...
static uint32_t kernel_vaddr_next = 0;

// lock used in page_fault_handler
static lock_t page_fault_lock;

/* Main API */

/* Use virtual address to get index in page directory. */
uint32_t get_dir_idx(uint32_t vaddr){
  return (vaddr & PAGE_DIRECTORY_MASK) >> PAGE_DIRECTORY_BITS;
}

/* Use virtual address to get index in a page table. */
uint32_t get_tab_idx(uint32_t vaddr){
  return (vaddr & PAGE_TABLE_MASK) >> PAGE_TABLE_BITS;
}

/* TODO: Returns physical address of page number i */
uint32_t* page_addr(int i){
  return (uint32_t *) (MEM_START + i*PAGE_SIZE);
}

/* Set flags in a page table entry to 'mode' */
void set_ptab_entry_flags(uint32_t * pdir, uint32_t vaddr, uint32_t mode){
  uint32_t dir_idx = get_dir_idx((uint32_t) vaddr);
  uint32_t tab_idx = get_tab_idx((uint32_t) vaddr);
  uint32_t dir_entry;
  uint32_t *tab;
  uint32_t entry;

  dir_entry = pdir[dir_idx];
  ASSERT(dir_entry & PE_P); /* dir entry present */
  tab = (uint32_t *) (dir_entry & PE_BASE_ADDR_MASK);
  /* clear table[index] bits 11..0 */
  entry = tab[tab_idx] & PE_BASE_ADDR_MASK;

  /* set table[index] bits 11..0 */
  entry |= mode & ~PE_BASE_ADDR_MASK;
  tab[tab_idx] = entry;

  /* Flush TLB because we just changed a page table entry in memory */
  flush_tlb_entry(vaddr);
}

/* Initialize a page table entry
 *  
 * 'vaddr' is the virtual address which is mapped to the physical
 * address 'paddr'. 'mode' sets bit [12..0] in the page table entry.
 *   
 * If user is nonzero, the page is mapped as accessible from a user
 * application.
 */
void init_ptab_entry(uint32_t * table, uint32_t vaddr,
         uint32_t paddr, uint32_t mode){
  int index = get_tab_idx(vaddr);
  table[index] =
    (paddr & PE_BASE_ADDR_MASK) | (mode & ~PE_BASE_ADDR_MASK);
  flush_tlb_entry(vaddr);
}

/* Insert a page table entry into the page directory. 
 *   
 * 'mode' sets bit [12..0] in the page table entry.
 */
void insert_ptab_dir(uint32_t * dir, uint32_t *tab, uint32_t vaddr, 
		       uint32_t mode){

  uint32_t access = mode & MODE_MASK;
  int idx = get_dir_idx(vaddr);

  dir[idx] = ((uint32_t)tab & PE_BASE_ADDR_MASK) | access;
}

/* TODO: Allocate a page. Return page index in the page_map directory.
 * 
 * Marks page as pinned if pinned == TRUE. 
 * Swap out a page if no space is available. 
 */
int page_alloc(int pinned){
  int index = -1;
  int i;
  for(i = 0; i < PAGEABLE_PAGES; i++) {
    if(page_map[i].free == 1) {
      index = i;
      break;
    }
  }

  if (index == -1) {
    index = page_replacement_policy();
    page_swap_out(index);

  }

  page_map[index].pinned = pinned;
  page_map[index].is_table = FALSE;
  page_map[index].free = FALSE;
  return index;
}

/* TODO: Set up kernel memory for kernel threads to run.
 *
 * This method is only called once by _start() in kernel.c, and is only 
 * supposed to set up the page directory and page tables for the kernel.
 */
void init_memory(void){
  uint32_t vaddr = 0;

  // initialize
  uint32_t vaddr = 0;
  int i, j;
  for (i = 0; i < PAGEABLE_PAGES; i++)
  {
    page_map[i].is_table = FALSE;
    page_map[i].free = TRUE;
    page_map[i].pinned = FALSE;
  }

  // pin page directory for kernel
  page_map[0].is_table = TRUE;
  page_map[0].free = FALSE;
  page_map[0].pinned = TRUE;
  kernel_pdir =page_addr(0);

  // modified by yuzeng
  //vaddr += PAGE_SIZE;

  // initialize the kernel page tables
  for (i = 0; i < N_KERNEL_PTS; i++)
  {
    page_map[i+1].free = FALSE;
    page_map[i+1].pinned = TRUE;
    // modified by yuzeng
    page_map[i+1].is_table = TRUE;
    
    kernel_ptabs[i] = page_addr(i+1);
    int mode = 7;
    insert_ptab_dir(kernel_pdir, kernel_ptabs[i], vaddr, mode);

    for (j = 0; j < PAGE_N_ENTRIES; j++)
    {
     vaddr += PAGE_SIZE;
     if (vaddr >= MEM_START)
       break;
     mode = 7;
     init_ptab_entry(kernel_ptabs[i], vaddr, vaddr, mode);
    }
  }


  // Give user permission to use the memory pages associated with the screen
  set_ptab_entry_flags(kernel_pdir, SCREEN_ADDR, 7 /* and more MODE??*/);
 
}


/* TODO: Set up a page directory and page table for a new 
 * user process or thread. */
// copied from memory_zy.c
void setup_page_table(pcb_t * p){
  // TODO: Not sure how many pages for each kernel
  if (p->is_thread) {
    p->page_directory = kernel_pdir;
    return;
  }

  // if it is process, set the directory
  uint32_t page_idx = page_alloc(1);
  page_map[page_idx].is_table = TRUE;
  p->page_directory = page_addr(page_idx);

  // set page table
  uint32_t vaddr = PROCESS_START;
  page_idx = page_alloc(1);
  page_map[page_idx].is_table = TRUE;
  insert_ptab_dir(p->page_directory, page_addr(page_idx), vaddr, PE_P|PE_RW|PE_US); // only one page table for each process ???
   
  uint32_t page_num = p->swap_size * SECTOR_SIZE / PAGE_SIZE; 
  uint32_t i;
  // write page table entries
  for(i = 0; i < page_num; i++) {
    uint32_t page_idx = page_alloc(0);
    uint32_t paddr = page_addr(page_idx);
    // get the table for kernel
    int idx = get_dir_idx(vaddr);    
    uint32_t table = p->page_directory[idx];
    uint32_t mode = 7;
    init_ptab_entry( table, vaddr, paddr, mode );
    vaddr += PAGE_SIZE;
  }
  
  // allocate stack page table
  page_idx = page_alloc(1);
  uint32_t stack_table = page_addr(page_idx);
  insert_ptab_dir(p->page_directory, stack_table, p->user_stack, PE_P|PE_RW|PE_US); // mode??

  // allocate stack pages
  for(i = 0; i < N_PROCESS_STACK_PAGES; i++) {
    page_idx = page_alloc(0);
    uint32_t stack_page = page_addr(page_idx);
    init_ptab_entry(stack_table, p->user_stack + i * PAGE_SIZE, stack_page, PE_P|PE_RW|PE_US);  // Does stack grow into higher address?
  }
  
}

/* TODO: Swap into a free page upon a page fault.
 * This method is called from interrupt.c: exception_14(). 
 * Should handle demand paging.
 */
void page_fault_handler(void){
  lock_acquire(&page_fault_lock);

  uint32_t vaddr = current_running->fault_addr; 


  current_running->page_fault_count++;
  int i = page_alloc(0); //require complete implementation of page_alloc!!

  page_swap_in(i);

  // remember to set swap_loc at beginning
  page_map[i].swap_loc = current_running->swap_loc;
  page_map[i].vaddr = vaddr;

  uint32_t dir = get_dir_idx(vaddr);
  init_ptab_entry(current_running->page_directory[dir], vaddr, page_addr(i), 7);

  lock_release(&page_fault_lock);
  
}

/* Get the sector number on disk of a process image
 * Used for page swapping. */
int get_disk_sector(page_map_entry_t * page){
  return page->swap_loc +
    ((page->vaddr - PROCESS_START) / PAGE_SIZE) * SECTORS_PER_PAGE;
}

/* TODO: Swap i-th page in from disk (i.e. the image file) */
void page_swap_in(int i){
  uint32_t * page_table;
  int dist_sector = get_disk_sector(&page_map[i]);

  scsi_read(disk_sector, SECTORS_PER_PAGE, (char *) page_addr(i));
  
}

/* TODO: Swap i-th page out to disk.
 *   
 * Write the page back to the process image.
 * There is no separate swap space on the USB.
 * 
 */
void page_swap_out(int i){

}


/* TODO: Decide which page to replace, return the page number  */
int page_replacement_policy(void){
 
}
