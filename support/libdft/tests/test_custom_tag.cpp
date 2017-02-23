/*-
 * Copyright (c) 2013, VU University
 * All rights reserved.
 *
 * This software was developed by Remco Vermeulen <r.vermeulen@vu.nl>
 * at VU University, Amsterdam, The Netherlands, somewhere in 2013.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Columbia University nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <config.h>
#include <libdft_api.h>

#include "libdft_test_api.h"
#include "minunit.h"

#ifndef USE_CUSTOM_TAG
#error "This test program is to test a custom tag!"
#endif

const char * test_set_tag_for_addr()
{
    int res = 0;
    int dummy;
    
    tag_t set_tag = tag_traits<tag_t>::set_val;
    res = libdft_test_set_addr((ADDRINT)&dummy, &set_tag);
    mu_assert(res != -1, "Failed to set tag!");

    return NULL;
}

const char * test_assert_tag_for_addr()
{
    int res = 0;
    int dummy;
    
    tag_t set_tag = tag_traits<tag_t>::set_val;
    res = libdft_test_set_addr((ADDRINT)&dummy, &set_tag);
    mu_assert(res != -1, "Failed to set tag!");

    res = libdft_test_assert_addr((ADDRINT)&dummy, &set_tag);
    mu_assert(res == 1, "The asserted tag is not equal!");

    return NULL;
}

const char * test_mov_tag_m2m()
{
    int res = 0;
    int src = 0, dst = 0;
    
    tag_t set_tag = tag_traits<tag_t>::set_val;
    tag_t cleared_tag = tag_traits<tag_t>::cleared_val;
    
    res = libdft_test_assert_addr((ADDRINT)&src, &cleared_tag);
    mu_assert(res == 1, "The src tag is already set!");

    res = libdft_test_set_addr((ADDRINT)&src, &set_tag);
    mu_assert(res != -1, "Failed to set src tag!");
    
    res = libdft_test_assert_addr((ADDRINT)&src, &set_tag);
    mu_assert(res == 1, "The src tag is incorrect!");
    
    res = libdft_test_assert_addr((ADDRINT)&dst, &cleared_tag);
    mu_assert(res == 1, "The dst tag is already set!");

    dst = src;
    
    res = libdft_test_assert_addr((ADDRINT)&dst, &set_tag);
    mu_assert(res == 1, "The destination tag is not equal to the source tag, tag propagation failed!");

    return NULL;
}

const char * test_mov_tag_r2r()
{
    int res = 0;
    
    tag_t set_tag = tag_traits<tag_t>::set_val;
    tag_t cleared_tag = tag_traits<tag_t>::cleared_val;

    res = libdft_test_assert_reg({GPR_EBX, 0}, &cleared_tag);
    mu_assert(res == 1, "The src tag is already set!");
    
    res = libdft_test_assert_reg({GPR_EBX, 1}, &cleared_tag);
    mu_assert(res == 1, "The dst tag is already set!");

    res = libdft_test_set_reg({ GPR_EBX, 0}, &set_tag);
    mu_assert(res != -1, "Failed to set src tag!");

    asm("movb %%bl, %%bh" ::: "ebx");
    
    res = libdft_test_assert_reg({GPR_EBX, 1}, &set_tag);
    mu_assert(res == 1, "The destination tag is not equal to the source tag, tag propagation failed!");
    
    res = libdft_test_assert_reg({GPR_EBX, 2}, &cleared_tag);
    mu_assert(res == 1, "Unexpected tag in the destination register!");
    
    res = libdft_test_assert_reg({GPR_EBX, 3}, &cleared_tag);
    mu_assert(res == 1, "Unexpected tag in the destination register!");

    return NULL;
}

const char * all_tests()
{
    mu_suite_start();
    mu_run_test(test_set_tag_for_addr);
    mu_run_test(test_assert_tag_for_addr);
    mu_run_test(test_mov_tag_m2m);
    mu_run_test(test_mov_tag_r2r);

    return NULL;
}

RUN_TESTS(all_tests)
