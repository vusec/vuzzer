#ifndef __TAGMAP_CUSTOM_H__
#define __TAGMAP_CUSTOM_H__
#include <array>

const unsigned long DIR_PAGE_BITS   = 12;
const unsigned long DIR_PAGE_SZ     = 1 << DIR_PAGE_BITS;
const unsigned long DIR_PAGE_MASK   = DIR_PAGE_SZ - 1;
const unsigned long DIR_TABLE_BITS  = 10;
const unsigned long DIR_TABLE_SZ    = 1 << DIR_TABLE_BITS;
const unsigned long DIR_TABLE_MASK  = DIR_TABLE_SZ - 1;
const unsigned long DIR_BITS        = 10;
const unsigned long DIR_SZ          = 1 << DIR_BITS;
const unsigned long DIR_MASK        = DIR_SZ - 1;

inline unsigned long virt2table(unsigned long addr) {
    return (addr >> (DIR_PAGE_BITS + DIR_TABLE_BITS)) & DIR_MASK;
}

inline unsigned long virt2page(unsigned long addr) {
    return (addr >> DIR_PAGE_BITS) & DIR_TABLE_MASK;
}

inline unsigned long virt2offset(unsigned long addr) {
    return addr & DIR_PAGE_MASK;
}

typedef std::array<tag_t, DIR_PAGE_SZ> tag_page_t;
typedef std::array<tag_page_t*, DIR_TABLE_SZ> tag_table_t;
typedef std::array<tag_table_t*, DIR_SZ> tag_dir_t;

extern int tagmap_all_tainted;
extern void libdft_die();

inline tag_t const * tag_dir_getb_as_ptr(tag_dir_t const & dir, ADDRINT addr) {
    if(dir[virt2table(addr)]) {
        tag_table_t * table = dir[virt2table(addr)];
        if ((*table)[virt2page(addr)]) {
            tag_page_t * page = (*table)[virt2page(addr)];
            if (page != NULL)
                return &(*page)[virt2offset(addr)];
        }
    }
    return &tag_traits<tag_t>::cleared_val;
}

inline tag_t tag_dir_getb(tag_dir_t const & dir, ADDRINT addr) {
    return *tag_dir_getb_as_ptr(dir, addr);
}


inline void tag_dir_setb(tag_dir_t & dir, ADDRINT addr, tag_t const & tag)
{
//    LOG("Setting tag "+hexstr(addr)+"\n");
    if(dir[virt2table(addr)] == NULL)
    {
        //LOG("No tag table for "+hexstr(addr)+" allocating new table\n");
        tag_table_t * new_table = new (nothrow) tag_table_t();
        if (new_table == NULL)
        {
            LOG("Failed to allocate tag table!\n");
            libdft_die();
        }
        dir[virt2table(addr)] = new_table;
    }

    tag_table_t * table = dir[virt2table(addr)];
    if ((*table)[virt2page(addr)] == NULL)
    {
        //LOG("No tag page for "+hexstr(addr)+" allocating new page\n");
        tag_page_t * new_page = new (nothrow) tag_page_t();
        if (new_page == NULL)
        {
            LOG("Failed to allocate tag page!\n");
            libdft_die();
        }
        std::fill(new_page->begin(), new_page->end(), tag_traits<tag_t>::cleared_val);
        (*table)[virt2page(addr)] = new_page; 
    }

    tag_page_t * page = (*table)[virt2page(addr)];
    //LOG("Writing tag for "+hexstr(addr)+"\n");
    (*page)[virt2offset(addr)] = tag;
}
#endif
