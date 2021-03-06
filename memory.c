/* Author(s): Yu Zeng, Yuyan Zhao
 * COS 318, Fall 2018: Project 5 Virtual Memory
 * Implementation of the memory manager for the kernel.
*/

// TODO: 
// 1. the first entry of process table should point to kernel page table, so that the interrupt could find the physical addr between 0 and 1MB 
// 2. on-demand paging!
// 3. every page should know its owner, so that when it is paged out, its present bit can be reset.

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
static uint32_t fifo_queue[PAGEABLE_PAGES];
static uint32_t head;
static uint32_t tail;
// for NRU algorithm
static uint32_t NN[PAGEABLE_PAGES];
static uint32_t NN_head;

static uint32_t NM[PAGEABLE_PAGES];
static uint32_t NM_head;

static uint32_t RN[PAGEABLE_PAGES];
static uint32_t RN_head;

static uint32_t RM[PAGEABLE_PAGES];
static uint32_t RM_head;

enum {
  FIFO = 0,
  FIFO_SECOND_CHANCE = 1,
  NRU = 2
};
static uint32_t ALGORITHM = NRU;

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

uint32_t get_ptab_entry(uint32_t * pdir, uint32_t vaddr) {
  uint32_t dir_idx = get_dir_idx((uint32_t) vaddr);
  uint32_t tab_idx = get_tab_idx((uint32_t) vaddr);
  uint32_t dir_entry;
  uint32_t *tab;
  uint32_t entry;

  dir_entry = pdir[dir_idx];
  ASSERT(dir_entry & PE_P); /* dir entry present */
  tab = (uint32_t *) (dir_entry & PE_BASE_ADDR_MASK);
  return tab[tab_idx];
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
// enqueue fifo operations are done in this function
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
  // modified by yuzeng
  if(!pinned){
    fifo_queue[head] = index;
    //page_map[index].chance = 1;
    head = (head + 1) % PAGEABLE_PAGES;
  }

  page_map[index].pinned = pinned;
  page_map[index].is_table = FALSE;
  page_map[index].free = FALSE;
  page_map[index].swap_size = current_running->swap_size;
  page_map[index].owner = current_running->pid;


  //bzero((char *)page_addr(index), PAGE_SIZE);
  for (i = 0; i < PAGE_N_ENTRIES; ++i) {
    bzero((char *)(page_addr(index) + i), sizeof(uint32_t) / sizeof(char));
  }

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
  lock_init(&page_fault_lock);
  head = tail = 0;
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

  for (i = 0; i < PAGE_N_ENTRIES; i++) {
    bzero((char *)(kernel_pdir[i]), sizeof(uint32_t) / sizeof(char));
  }

  // modified by yuzeng
  // vaddr += PAGE_SIZE;

  // initialize the kernel page tables
  for (i = 0; i < N_KERNEL_PTS; i++)
  {
    page_map[i+1].free = FALSE;
    page_map[i+1].pinned = TRUE;
    // modified by yuzeng
    page_map[i+1].is_table = TRUE;
    
    kernel_ptabs[i] = page_addr(i+1);
    insert_ptab_dir(kernel_pdir, kernel_ptabs[i], vaddr, PE_P | PE_RW);

    for (j = 0; j < PAGE_N_ENTRIES; j++)
    {
      if (vaddr >= MAX_PHYSICAL_MEMORY) {
        break;
      }
      init_ptab_entry((uint32_t) kernel_ptabs[i] & PE_BASE_ADDR_MASK, vaddr, vaddr, PE_P | PE_RW);
       vaddr += PAGE_SIZE;
    }
  }


  // Give user permission to use the memory pages associated with the screen
  set_ptab_entry_flags(kernel_pdir, SCREEN_ADDR, PE_RW | PE_P | PE_US/* and more MODE??*/);
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
  insert_ptab_dir(p->page_directory, kernel_ptabs[0], 0, 7);


  uint32_t i;
  for (i = 0; i < PAGE_N_ENTRIES; ++i) {
    bzero((char *)(p->page_directory[i]), sizeof(uint32_t) / sizeof(char));
  }

  // set page table
  uint32_t vaddr = PROCESS_START;
  page_idx = page_alloc(1);
  page_map[page_idx].is_table = TRUE;
  insert_ptab_dir(p->page_directory, page_addr(page_idx), vaddr, 7); // only one page table for each process ???
  //insert_ptab_dir(p->page_directory, page_addr(page_idx), vaddr, PE_P|PE_RW|PE_US); // only one page table for each process ???
   
  // uint32_t page_num = p->swap_size * SECTOR_SIZE / PAGE_SIZE; 
  // // write page table entries
  // for(i = 0; i < page_num; i++) {
  //   uint32_t page_idx = page_alloc(0);
  //   uint32_t paddr = page_addr(page_idx);
  //   // get the table for kernel
  //   int idx = get_dir_idx(vaddr);    
  //   uint32_t table = p->page_directory[idx];
  //   uint32_t mode = 7;
  //   page_map[page_idx].swap_loc = p->swap_loc;
  //   page_map[page_idx].vaddr = vaddr;
  //   init_ptab_entry( table, vaddr, paddr, mode );
  //   vaddr += PAGE_SIZE;
  // }
  
  // allocate stack page table
  page_idx = page_alloc(1);
  uint32_t stack_table = page_addr(page_idx);
  insert_ptab_dir(p->page_directory, stack_table, p->user_stack, PE_P|PE_RW|PE_US); // mode??

  // allocate stack pages
  for(i = 0; i < N_PROCESS_STACK_PAGES; i++) {
    page_idx = page_alloc(1);
    uint32_t stack_page = page_addr(page_idx);
    init_ptab_entry(stack_table & PE_BASE_ADDR_MASK, p->user_stack - i * PAGE_SIZE, stack_page, PE_P|PE_RW|PE_US);  // Does stack grow into higher address?
  }
  
}

/* TODO: Swap into a free page upon a page fault.
 * This method is called from interrupt.c: exception_14(). 
 * Should handle demand paging.
 */
void page_fault_handler(void){
  // debug
  //scrprintf(1, 1, "%d:%d enter page_fault_handler", get_timer(), current_running->pid);
  lock_acquire(&page_fault_lock);

  uint32_t vaddr = current_running->fault_addr; 


  current_running->page_fault_count++;
  int i = page_alloc(0); 

  page_map[i].swap_loc = current_running->swap_loc;
  page_map[i].swap_size = current_running->swap_size;
  page_map[i].vaddr = vaddr;
  page_map[i].pdir = current_running->page_directory;

  // page_map[i].swap_loc = current_running->swap_loc;
  // page_map[i].vaddr = vaddr;

  page_swap_in(i);

  uint32_t dir = get_dir_idx(vaddr);
  init_ptab_entry(current_running->page_directory[dir] & PE_BASE_ADDR_MASK, vaddr, page_addr(i), PE_P | PE_RW | PE_US);

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
  int disk_sector = get_disk_sector(&page_map[i]);

  //regular page 
  if ((disk_sector + SECTORS_PER_PAGE) <= (page_map[i].swap_loc + page_map[i].swap_size)) {
    scsi_read(disk_sector, SECTORS_PER_PAGE, (char *)page_addr(i)); 
  }
  
  //last page
  else {  
    int diff = (disk_sector + SECTORS_PER_PAGE) - (page_map[i].swap_loc + page_map[i].swap_size);
     scsi_read(disk_sector, SECTORS_PER_PAGE - diff, (char *)page_addr(i)); 
  }
}

/* TODO: Swap i-th page out to disk.
 *   
 * Write the page back to the process image.
 * There is no separate swap space on the USB.
 * 
 */
void page_swap_out(int i){
  int disk_sector = get_disk_sector(&page_map[i]);
  set_ptab_entry_flags(page_map[i].pdir, page_map[i].vaddr, PE_RW | PE_US ); 

  uint32_t ptab_entry = get_ptab_entry(page_map[i].pdir, page_map[i].vaddr);
  bool_t dirty;
  if (ptab_entry & PE_D > 0) {
    dirty = TRUE;
  }
  else {
    dirty = FALSE;
  }

  if (1) {
    // regular page
    if ((disk_sector + SECTORS_PER_PAGE) <= (page_map[i].swap_loc + page_map[i].swap_size))
      scsi_write(disk_sector, SECTORS_PER_PAGE, (char *)page_addr(i)); 
    
    // last page 
    else {  
      int diff = (disk_sector + SECTORS_PER_PAGE) - (page_map[i].swap_loc + page_map[i].swap_size);
      scsi_write(disk_sector, SECTORS_PER_PAGE - diff, (char *)page_addr(i)); 
    }
  }

  page_map[i].free = TRUE; 

  flush_tlb_entry(page_map[i].vaddr);
  
}


/* TODO: Decide which page to replace, return the page number  */
int page_replacement_policy(void){
  if (ALGORITHM == FIFO) {
    if(head == tail) 
      ASSERT(0);
    int prev_tail = tail;
    tail = (tail + 1) % PAGEABLE_PAGES;
    return fifo_queue[prev_tail];
  }
  else if (ALGORITHM == FIFO_SECOND_CHANCE) {
    if(head == tail)
      ASSERT(0);
    uint32_t ptab_entry;
    while(1) {
      int page_idx = fifo_queue[tail];
      ptab_entry = get_ptab_entry(page_map[page_idx].pdir, page_map[page_idx].vaddr);
      if(ptab_entry & PE_A) {
        set_ptab_entry_flags(page_map[page_idx].pdir, page_map[page_idx].vaddr, (ptab_entry & ~PE_A));
        flush_tlb_entry(page_map[page_idx].vaddr);
        fifo_queue[head] = fifo_queue[tail];   
        head = (head + 1) % PAGEABLE_PAGES;         
        tail = (tail + 1) % PAGEABLE_PAGES;      
      }
      else
        break;
    }
    int prev_tail = tail;
    tail = (tail + 1) % PAGEABLE_PAGES;    
    return fifo_queue[prev_tail];  
  }
  else if (ALGORITHM == NRU) {
    // loop all the pages in queue and put into 4 queues
    if(head == tail) {
      ASSERT(0);
    }
    uint32_t i;
    uint32_t page_idx;
    bool_t R;
    bool_t M;
    uint32_t ptab_entry;
    uint32_t return_page_idx;
    NN_head = 0;
    NM_head = 0;
    RN_head = 0;
    RM_head = 0;
    for(i = tail; i != head; i = (i+1) % PAGEABLE_PAGES) {
      page_idx = fifo_queue[i];
      ptab_entry = get_ptab_entry(page_map[page_idx].pdir, page_map[page_idx].vaddr);
      if ((ptab_entry & PE_A) > 0) {
        R = TRUE;
      }
      else {
        R = FALSE;
      }

      if ((ptab_entry & PE_D) > 0) {
        M = TRUE;
      }
      else {
        M = FALSE;
      }

      if(!R && !M) {
        NN[NN_head++] = page_idx;
      }
      else if(!R && M) {
        NM[NM_head++] = page_idx;
      }
      else if(R && !M) {
        RN[RN_head++] = page_idx;
      }
      else {
        RM[RM_head++] = page_idx;
      }      
    }
    // Randomly select one page from the lowest unempty queue
    if (NN_head != 0) {
      return_page_idx = NN[rand() % NN_head];
    }
    else if(NM_head != 0) {
      return_page_idx = NM[rand() % NM_head];
    }
    else if(RN_head != 0) {
      return_page_idx = RN[rand() % RN_head];
    }
    else {
      return_page_idx = RM[rand() % RM_head];
    }

    for(i = tail; i != head; i = (i+1) % PAGEABLE_PAGES) {
      // clear reference/access bits
      page_idx = fifo_queue[i]; 
      ptab_entry = get_ptab_entry(page_map[page_idx].pdir, page_map[page_idx].vaddr);
      set_ptab_entry_flags(page_map[page_idx].pdir, page_map[page_idx].vaddr, (ptab_entry & ~PE_A));
      flush_tlb_entry(page_map[page_idx].vaddr);
    }    

    for(i = tail; i != head; i = (i+1) % PAGEABLE_PAGES) {
      page_idx = fifo_queue[i]; 
      if(page_idx != return_page_idx) {
        continue;
      }
      fifo_queue[i] = fifo_queue[tail];
      tail = (tail + 1) % PAGEABLE_PAGES;
      break;
    }  
    return return_page_idx;
  }
  else
    ASSERT(0); 
}
