#ifndef __LIBDFT_TEST_API_H__
#define __LIBDFT_TEST_API_H__

#include "config.h"

enum test_cmd_type {TEST_CLR_TAG, TEST_GET_TAG, TEST_SET_TAG, TEST_ASSERT_TAG};
enum test_cmd_subject {TEST_ADDR, TEST_REG};

struct libdft_test_cmd_t
{
    test_cmd_type type;
    test_cmd_subject subject;
    union 
    {
        ADDRINT addr;
#ifdef USE_CUSTOM_TAG
        gpr_idx reg;
#else
        uint32_t reg;
#endif
    };
#ifdef USE_CUSTOM_TAG
    tag_t * tag;
#else
    uint8_t tag;
#endif
};

int libdft_test_clr_addr(ADDRINT addr);
#ifdef USE_CUSTOM_TAG
int libdft_test_clr_reg(gpr_idx reg);
#else
int libdft_test_clr_reg(uint32_t reg);
#endif

/* Returns 0 on success and -1 on failure. */
#ifdef USE_CUSTOM_TAG
int libdft_test_set_addr(ADDRINT addr, tag_t * tag);
int libdft_test_set_reg(gpr_idx reg, tag_t * tag);
#else
int libdft_test_set_addr(ADDRINT addr, uint8_t tag);
int libdft_test_set_reg(uint32_t reg, uint8_t tag);
#endif

/* Returns valid pointer on success, NULL if there is no tag and  -1 on failure. */
#ifdef USE_CUSTOM_TAG
tag_t * libdft_test_get_addr(ADDRINT addr);
tag_t * libdft_test_get_reg(gpr_idx reg);
#else
uint8_t libdft_test_get_addr(ADDRINT addr);
uint8_t libdft_test_get_reg(uint32_t reg);
#endif

/* Returns 0 or 1 if false or true, and -1 of failure.*/
#ifdef USE_CUSTOM_TAG
int libdft_test_assert_addr(ADDRINT addr, tag_t * tag);
int libdft_test_assert_reg(gpr_idx reg, tag_t * tag);
#else
int libdft_test_assert_addr(ADDRINT addr, uint8_t tag);
int libdft_test_assert_reg(uint32_t reg, uint8_t tag);
#endif

#endif
