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

#include <stdio.h>
#include <stdlib.h>

#include "config.h"
#include "branch_pred.h"
#include "libdft_api.h"
#include "libdft_test_api.h"
#include "syscall_desc.h"
#include "pin.H"

#include "tagmap.h"

void replace_api_dummy(IMG image, void * opaque);
bool replaced_api_dummy = false;

extern REG thread_ctx_ptr;

int do_cmd_handler(libdft_test_cmd_t * cmd, thread_ctx_t * thread_ctx)
{
    if (cmd == NULL)
    {
        LOG("Received invalid test command reference!\n");
        return -1;
    }
    
    switch(cmd->type)
    {
        case TEST_CLR_TAG:
            if (cmd->subject == TEST_ADDR)
            {
                LOG("Clearing tag at address " + hexstr(cmd->addr) + "\n");
                tagmap_clrb(cmd->addr);
            }
            else if (cmd->subject == TEST_REG)
            {
                LOG("Clearing tag at byte " + hexstr(cmd->reg.idx)+ " of register " + hexstr(cmd->reg.reg) + "\n");
                thread_ctx->vcpu.gpr[cmd->reg.reg][cmd->reg.idx] = tag_traits<tag_t>::cleared_val;
            }
            else LOG("Unexpected test subject, ignoring command!\n");
            break;
        case TEST_GET_TAG:
            if (cmd->subject == TEST_ADDR)
            {
                LOG("Getting tag at address " + hexstr(cmd->addr) + "\n");
#ifdef USE_CUSTOM_TAG
                return reinterpret_cast<int>(tagmap_getb_as_ptr(cmd->addr));
#else
                return reinterpret_cast<int>(tagmap_getb(cmd->addr));
#endif
            }
            else if (cmd->subject == TEST_REG)
            {
                LOG("Getting tag at byte " + hexstr(cmd->reg.idx)+ " of register " + hexstr(cmd->reg.reg) + "\n");
                return reinterpret_cast<int>(&thread_ctx->vcpu.gpr[cmd->reg.reg][cmd->reg.idx]);
            }
            else LOG("Unexpected test subject, ignoring command!\n");
            break;
        case TEST_SET_TAG:
            if (cmd->tag == NULL)
            {
                LOG("Skipping set tag command because of invalid tag pointer!.\n");
                return -1;
            }

            if (cmd->subject == TEST_ADDR)
            {
                LOG("Setting tag at " + hexstr(cmd->addr) + "\n");
                tagmap_setb_with_tag(cmd->addr, *cmd->tag);
            }
            else if (cmd->subject == TEST_REG)
            {
                LOG("Setting tag at byte " + hexstr(cmd->reg.idx)+ " of register " + hexstr(cmd->reg.reg) + "\n");
                thread_ctx->vcpu.gpr[cmd->reg.reg][cmd->reg.idx] = *cmd->tag;
            }
            else LOG("Unexpected test subject, ignoring command!\n");
            break;
        case TEST_ASSERT_TAG:
            if (cmd->tag == NULL)
            {
                LOG("Skipping assert tag command because of invalid tag pointer!.\n");
                return -1;
            }

            if (cmd->subject == TEST_ADDR)
            {
                LOG("Asserting tag at " + hexstr(cmd->addr)+ "\n");
                tag_t  tag = tagmap_getb(cmd->addr);
                return tag == *cmd->tag;
            }
            else if (cmd->subject == TEST_REG)
            {
                LOG("Asserting tag at byte " + hexstr(cmd->reg.idx)+ " of register " + hexstr(cmd->reg.reg) + "\n");
                return thread_ctx->vcpu.gpr[cmd->reg.reg][cmd->reg.idx] == *cmd->tag;
            }
            else LOG("Unexpected test subject, ignoring command!\n");
            break;
        default:
            LOG("Received and ignored unknown command!\n");
            break;
    };

    return 0;
}

/* 
 * Tool used for verifying that libdft propagates taint correctly.
 */
int main(int argc, char **argv)
{
	/* initialize symbol processing */
	PIN_InitSymbols();
	/* initialize Pin; optimized branch */
	if (unlikely(PIN_Init(argc, argv)))
		/* Pin initialization failed */
		goto err;

    LOG("Instrumenting API.\n");
    IMG_AddInstrumentFunction(replace_api_dummy, NULL);

    LOG("Initializing libdft\n");
	/* initialize the core tagging engine */
	if (unlikely(libdft_init() != 0))
		/* failed */
		goto err;
	
	/* start Pin */
    LOG("Starting program.\n");
	PIN_StartProgram();
	
	/* typically not reached; make the compiler happy */
	return EXIT_SUCCESS;

err:
	/* error handling */

	/* detach from the process */
	libdft_die();

	/* return */
	return EXIT_FAILURE;
}

void replace_api_dummy(IMG img, void * opaque)
{
    if (replaced_api_dummy) return;

    RTN rtn = RTN_FindByName(img, "do_cmd");
    if (RTN_Valid(rtn) == FALSE) 
    {
        LOG("Failed to instrument test API!\n");
        exit(EXIT_FAILURE);
    }

    PROTO proto_do_cmd = PROTO_Allocate( PIN_PARG(int), CALLINGSTD_DEFAULT,
            "do_cmd", PIN_PARG(libdft_test_cmd_t *), PIN_PARG_END() );

    RTN_ReplaceSignature(rtn, AFUNPTR(do_cmd_handler), IARG_PROTOTYPE, proto_do_cmd, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_REG_VALUE, thread_ctx_ptr, IARG_END);

    replaced_api_dummy = true;
}
