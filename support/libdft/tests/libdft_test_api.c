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
#include <sys/types.h>

#include "pin.H"
#include "tagmap.h"
#include "libdft_api.h"
#include "libdft_test_api.h"

/* This function will be replaced by the test tool.
 * Therefore we use C linkage and prevent it from being inlined. */
extern "C" int do_cmd(libdft_test_cmd_t * cmd) __attribute__ ((noinline));

int do_cmd(libdft_test_cmd_t * cmd)
{
    const char * trap  = "\xCC";

    ((void (*) (void))trap)();

    /* Just to satisfy the compiler */
    return 0xDEADBEEF;
}

int libdft_test_clr_addr(ADDRINT addr)
{
#ifdef USE_CUSTOM_TAG
    tag_t cleared_tag = tag_traits<tag_t>::cleared_val;
    libdft_test_cmd_t cmd{TEST_CLR_TAG, TEST_ADDR, {addr: addr}, &cleared_tag};
#else
    libdft_test_cmd_t cmd{TEST_CLR_TAG, TEST_ADDR, {addr: addr}, 0};
#endif
    if (do_cmd(&cmd) == -1 ) return -1;

    return 0;
}

#ifdef USE_CUSTOM_TAG
int libdft_test_clr_reg(gpr_idx reg)
#else
int libdft_test_clr_reg(uint32_t reg)
#endif
{
#ifdef USE_CUSTOM_TAG
    tag_t cleared_tag = tag_traits<tag_t>::cleared_val;
    libdft_test_cmd_t cmd{TEST_CLR_TAG, TEST_REG, {reg: reg}, &cleared_tag};
#else
    libdft_test_cmd_t cmd{TEST_CLR_TAG, TEST_REG, {reg: reg}, 0};
#endif
    if (do_cmd(&cmd) == -1 ) return -1;

    return 0;
}

#ifdef USE_CUSTOM_TAG
int libdft_test_set_addr(ADDRINT addr, tag_t * tag)
#else
int libdft_test_set_addr(ADDRINT addr, uint8_t tag)
#endif
{
    libdft_test_cmd_t cmd{TEST_SET_TAG, TEST_ADDR, {addr: addr}, tag};
    if (do_cmd(&cmd) == -1 ) return -1;

    return 0;
}

#ifdef USE_CUSTOM_TAG
int libdft_test_set_reg(gpr_idx reg, tag_t * tag)
#else
int libdft_test_set_reg(uint32_t reg, uint8_t tag)
#endif
{
    libdft_test_cmd_t cmd{TEST_SET_TAG, TEST_REG, {reg: reg}, tag};
    if (do_cmd(&cmd) == -1 ) return -1;

    return 0;
}

#ifdef USE_CUSTOM_TAG
tag_t * libdft_test_get_addr(ADDRINT addr)
#else
uint8_t libdft_test_get_addr(ADDRINT addr)
#endif
{
    libdft_test_cmd_t cmd{TEST_GET_TAG, TEST_ADDR, {addr: addr}, 0};
    int res = do_cmd(&cmd);

#ifdef USE_CUSTOM_TAG
    if (res == -1) return (tag_t*) -1;
    return (tag_t*)res;
#else
    if (res == -1) return (uint8_t) -1;
    return (uint8_t)res;
#endif
}

#ifdef USE_CUSTOM_TAG
tag_t * libdft_test_get_reg(gpr_idx reg)
#else
uint8_t libdft_test_get_reg(uint32_t reg)
#endif
{
    libdft_test_cmd_t cmd{TEST_GET_TAG, TEST_REG, {reg: reg}, 0};
    int res = do_cmd(&cmd);

#ifdef USE_CUSTOM_TAG
    if (res == -1) return (tag_t*) -1;
    return (tag_t*)res;
#else
    if (res == -1) return (uint8_t) -1;
    return (uint8_t)res;
#endif
}

#ifdef USE_CUSTOM_TAG
int libdft_test_assert_addr(ADDRINT addr, tag_t * tag)
#else
int libdft_test_assert_addr(ADDRINT addr, uint8_t tag)
#endif
{
    libdft_test_cmd_t cmd{TEST_ASSERT_TAG, TEST_ADDR, {addr: addr}, tag};
    return do_cmd(&cmd);
}

#ifdef USE_CUSTOM_TAG
int libdft_test_assert_reg(gpr_idx reg, tag_t * tag)
#else
int libdft_test_assert_reg(uint32_t reg, uint8_t tag)
#endif
{
    libdft_test_cmd_t cmd{TEST_ASSERT_TAG, TEST_REG, {reg: reg}, tag};
    return do_cmd(&cmd);
}
