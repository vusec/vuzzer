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

const char * test_clear_tag()
{
    int res = 0;

    res = libdft_test_clr_addr(0xDEADBEEF);
    mu_assert(res == 0, "Failed to clear the tag for address 0xDEADBEEF!");
    
#ifdef USE_CUSTOM_TAG
    res = libdft_test_clr_reg({GPR_EAX, 0});
#else
    res = libdft_test_clr_reg(GPR_EAX);
#endif
    mu_assert(res == 0, "Failed to clear a tag of register EAX!");

    return NULL;
}

const char * test_set_tag()
{
    int res = 0;
#ifdef USE_CUSTOM_TAG
    tag_t set_tag = tag_traits<tag_t>::set_val;
    res = libdft_test_set_addr(0xDEADBEEF, &set_tag);
#else
    res = libdft_test_set_addr(0xDEADBEEF, 1);
#endif
    mu_assert(res == 0, "Failed to set a tag for address 0xDEADBEEF!");
    
    res = libdft_test_set_addr(0xDEADBEEF, NULL);
    mu_assert(res == -1, "Successfully set a NULL tag for address 0xDEADBEEF!");

#ifdef USE_CUSTOM_TAG
    res = libdft_test_set_reg({GPR_EAX, 0}, &set_tag);
#else
    res = libdft_test_set_reg(GPR_EAX, 1);
#endif
    mu_assert(res == 0, "Failed to set a tag for register EAX!");

#ifdef USE_CUSTOM_TAG
    res = libdft_test_set_reg({GPR_EAX, 0}, NULL);
#else
    res = libdft_test_set_reg(GPR_EAX, 0);
#endif
    mu_assert(res == -1, "Successfully set a NULL tag for register EAX!");

    return NULL;
}

const char * test_get_tag()
{
    int res = 0;
    res = (int) libdft_test_get_addr(0xDEADBEEF);
    mu_assert(res != 0, "Failed to get a tag for address 0xDEADBEEF!");

#ifdef USE_CUSTOM_TAG
    res = (int) libdft_test_get_reg({GPR_EAX, 0});
#else
    res = (int) libdft_test_get_reg(GPR_EAX);
#endif
    mu_assert(res != 0, "Failed to get a tag for register EAX!");

    return NULL;
}

const char * test_assert_tag()
{
    int res = 0;

#ifdef USE_CUSTOM_TAG
    tag_t set_tag = tag_traits<tag_t>::set_val;
    res = libdft_test_set_addr(0xDEADBEEF, &set_tag);
#else
    res = libdft_test_set_addr(0xDEADBEEF, 1);
#endif
    mu_assert(res == 0, "Failed to set a tag for address 0xDEADBEEF!");
#ifdef USE_CUSTOM_TAG
    /* Returns 0 or 1 if false or true, and -1 of failure.*/
    res = libdft_test_assert_addr(0xDEADBEEF, &set_tag);
#else
    res = libdft_test_assert_addr(0xDEADBEEF, 1);
#endif
    mu_assert(res == 1, "Assertion of tag at address 0xDEADBEEF failed!");

    /* Since the test program is being taint tracked, make sure not to assert tags
     * for register that are modified by the ABI, otherwise the test might fail while
     * the program actually works correct!. EAX for example is bad register to use for this
     * because it holds the return value of a call! */
#ifdef USE_CUSTOM_TAG
    res = libdft_test_set_reg({GPR_EBX, 0}, &set_tag);
#else
    res = libdft_test_set_reg(GPR_EBX, 1);
#endif
    mu_assert(res == 0, "Failed to set a tag for register EAX!");

#ifdef USE_CUSTOM_TAG
    res = libdft_test_assert_reg({GPR_EBX, 0}, &set_tag);
#else
    res = libdft_test_assert_reg(GPR_EBX, 1);
#endif
    mu_assert(res == 1, "Assertion of tag at register EAX failed!");

    return NULL;
}

const char * all_tests()
{
    mu_suite_start();
    mu_run_test(test_clear_tag);
    mu_run_test(test_set_tag);
    mu_run_test(test_get_tag);
    mu_run_test(test_assert_tag);

    return NULL;
}

RUN_TESTS(all_tests);
