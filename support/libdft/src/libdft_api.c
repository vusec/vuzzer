/*-
 * Copyright (c) 2010, 2011, 2012, 2013, Columbia University
 * All rights reserved.
 *
 * This software was developed by Vasileios P. Kemerlis <vpk@cs.columbia.edu>
 * at Columbia University, New York, NY, USA, in June 2010.
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

/*
 * 06/03/2011:
 * 	the array structure that kept the per-thread contexts has been
 * 	replaced by TLS-like logic for performance and safety reasons;
 * 	Vasileios P. Kemerlis(vpk@cs.columbia.edu)
 */

#include <errno.h>
#include <iostream>
#include <fstream>
#include <string.h>
#include <unistd.h>

#include "libdft_api.h"
#include "libdft_core.h"
#include "syscall_desc.h"
#include "tagmap.h"
#include "branch_pred.h"


/* 
 * thread context pointer (TLS emulation); we
 * spill a register for emulating TLS-like storage.
 * Specifically, thread_ctx_ptr shall hold the
 * address of a per-thread context structure
 */
REG thread_ctx_ptr;

/* syscall descriptors */
extern syscall_desc_t syscall_desc[SYSCALL_MAX];

/* ins descriptors */
ins_desc_t ins_desc[XED_ICLASS_LAST];

/*
 * thread start callback (analysis function)
 *
 * allocate space for the syscall context and VCPUs
 * (i.e., thread context), and set the TLS-like pointer
 * (i.e., thread_ctx_ptr) accordingly
 *
 * @tid:	thread id
 * @ctx:	CPU context
 * @flags:	OS specific flags for the new thread
 * @v:		callback value
 */
static void
thread_alloc(THREADID tid, CONTEXT *ctx, INT32 flags, VOID *v)
{
	/* thread context pointer (ptr) */
	thread_ctx_t *tctx = NULL;

	tctx = new thread_ctx_t();
	/* allocate space for the thread context; optimized branch */
	if (unlikely(tctx == NULL)) { 
		/* error message */
		LOG(string(__func__) + ": thread_ctx_t allocation failed (" +
				string(strerror(errno)) + ")\n");
		
		/* die */
		libdft_die();
	}

	/* save the address of the per-thread context to the spilled register */
	PIN_SetContextReg(ctx, thread_ctx_ptr, (ADDRINT)tctx);
}

/*
 * thread finish callback (analysis function)
 *
 * free the space for the syscall context and VCPUs
 *
 * @tid:	thread id
 * @ctx:	CPU context
 * @code:	OS specific termination code for the thread
 * @v:		callback value
 */
static void
thread_free(THREADID tid, const CONTEXT *ctx, INT32 code, VOID *v)
{
	/* get the thread context */
	thread_ctx_t *tctx = (thread_ctx_t *)
		PIN_GetContextReg(ctx, thread_ctx_ptr);

	/* free the allocated space */
	free(tctx);
}

ADDRINT arg0;
ADDRINT *args;
/* 
 * syscall enter notification (analysis function)
 *
 * save the system call context and invoke the pre-syscall callback
 * function (if registered)
 *
 * @tid:	thread id
 * @ctx:	CPU context
 * @std:	syscall standard (e.g., Linux IA-32, IA-64, etc)
 * @v:		callback value
 */
static void
sysenter_save(THREADID tid, CONTEXT *ctx, SYSCALL_STANDARD std, VOID *v)
{
	/* get the thread context */
	thread_ctx_t *thread_ctx = (thread_ctx_t *)
		PIN_GetContextReg(ctx, thread_ctx_ptr);

	/* get the syscall number */
	size_t syscall_nr = PIN_GetSyscallNumber(ctx, std);

	/* unknown syscall; optimized branch */
	if (unlikely(syscall_nr >= SYSCALL_MAX)) {
		LOG(string(__func__) + ": unknown syscall (num=" +
				decstr(syscall_nr) + ")\n");
		/* syscall number is set to -1; hint for the sysexit_save() */
		thread_ctx->syscall_ctx.nr = -1;
		/* no context save and no pre-syscall callback invocation */
		return;
	}

	/* pass the system call number to sysexit_save() */
	thread_ctx->syscall_ctx.nr = syscall_nr;

	/*
	 * check if we need to save the arguments for that syscall
	 *
	 * we save only when we have a callback registered or the syscall
	 * returns a value in the arguments
	 */
	if (syscall_desc[syscall_nr].save_args |
		syscall_desc[syscall_nr].retval_args) {
		/*
		 * dump only the appropriate number of arguments
		 * or yet another lame way to avoid a loop (vpk)
		 */
		if(syscall_nr == SYS_mmap){
			arg0 = PIN_GetSyscallArgument(ctx, std, SYSCALL_ARG0);
			args = reinterpret_cast<ADDRINT *>(arg0);
			thread_ctx->syscall_ctx.arg[SYSCALL_ARG0] = args[0];	
			thread_ctx->syscall_ctx.arg[SYSCALL_ARG1] = args[1];		
			thread_ctx->syscall_ctx.arg[SYSCALL_ARG2] = args[2];		
			thread_ctx->syscall_ctx.arg[SYSCALL_ARG3] = args[3];		
			thread_ctx->syscall_ctx.arg[SYSCALL_ARG4] = args[4];		
			thread_ctx->syscall_ctx.arg[SYSCALL_ARG5] = args[5];		
		}else{
		switch (syscall_desc[syscall_nr].nargs) {
			/* 6 */
			case SYSCALL_ARG5 + 1:
				thread_ctx->syscall_ctx.arg[SYSCALL_ARG5] =
					PIN_GetSyscallArgument(ctx,
								std,
								SYSCALL_ARG5);
			/* 5 */
			case SYSCALL_ARG4 + 1:
				thread_ctx->syscall_ctx.arg[SYSCALL_ARG4] =
					PIN_GetSyscallArgument(ctx,
								std,
								SYSCALL_ARG4);
			/* 4 */
			case SYSCALL_ARG3 + 1:
				thread_ctx->syscall_ctx.arg[SYSCALL_ARG3] =
					PIN_GetSyscallArgument(ctx,
								std,
								SYSCALL_ARG3);
			/* 3 */
			case SYSCALL_ARG2 + 1:
				thread_ctx->syscall_ctx.arg[SYSCALL_ARG2] =
					PIN_GetSyscallArgument(ctx,
								std,
								SYSCALL_ARG2);
			/* 2 */
			case SYSCALL_ARG1 + 1:
				thread_ctx->syscall_ctx.arg[SYSCALL_ARG1] =
					PIN_GetSyscallArgument(ctx,
								std,
								SYSCALL_ARG1);
			/* 1 */
			case SYSCALL_ARG0 + 1:
				thread_ctx->syscall_ctx.arg[SYSCALL_ARG0] =
					PIN_GetSyscallArgument(ctx,
								std,
								SYSCALL_ARG0);
			/* default */
			default:
				/* nothing to do */
				break;
		}
		}

		/* 
		 * dump the architectural state of the processor;
		 * saved as "auxiliary" data
		 */
		thread_ctx->syscall_ctx.aux = ctx;

		/* call the pre-syscall callback (if any) */
		if (syscall_desc[syscall_nr].pre != NULL)
			syscall_desc[syscall_nr].pre(&thread_ctx->syscall_ctx);
	}
}

/* 
 * syscall exit notification (analysis function)
 *
 * save the system call context and invoke the post-syscall callback
 * function (if registered)
 *
 * NOTE: it performs tag cleanup for the syscalls that have side-effects in
 * their arguments
 *
 * @tid:	thread id
 * @ctx:	CPU context
 * @std:	syscall standard (e.g., Linux IA-32, IA-64, etc)
 * @v:		callback value
 */
static void
sysexit_save(THREADID tid, CONTEXT *ctx, SYSCALL_STANDARD std, VOID *v)
{
	/* iterator */
	size_t i;

	/* get the thread context */
	thread_ctx_t *thread_ctx = (thread_ctx_t *)
		PIN_GetContextReg(ctx, thread_ctx_ptr);

	/* get the syscall number */
	int syscall_nr = thread_ctx->syscall_ctx.nr;
	
	/* unknown syscall; optimized branch */
	if (unlikely(syscall_nr < 0)) {
		LOG(string(__func__) + ": unknown syscall (num=" +
				decstr(syscall_nr) + ")\n");
		/* no context save and no pre-syscall callback invocation */
		return;
	}
	
	/*
	 * check if we need to save the arguments for that syscall
	 *
	 * we save only when we have a callback registered or the syscall
	 * returns a value in the arguments
	 */
	if (syscall_desc[syscall_nr].save_args |
			syscall_desc[syscall_nr].retval_args) {
		/* dump only the appropriate number of arguments */
		thread_ctx->syscall_ctx.ret = PIN_GetSyscallReturn(ctx, std);

		/* 
		 * dump the architectural state of the processor;
		 * saved as "auxiliary" data
		 */
		thread_ctx->syscall_ctx.aux = ctx;

		/* thread_ctx->syscall_ctx.errno =
			PIN_GetSyscallErrno(ctx, std); */
	
		/* call the post-syscall callback (if any) */
		if (syscall_desc[syscall_nr].post != NULL)
			syscall_desc[syscall_nr].post(&thread_ctx->syscall_ctx);
		else {
			/* default post-syscall handling */

			/* 
			 * the syscall failed; typically 0 and positive
			 * return values indicate success
			 */
			if (thread_ctx->syscall_ctx.ret < 0)
				/* no need to do anything */
				return;

			/* traverse the arguments map */
			for (i = 0; i < syscall_desc[syscall_nr].nargs; i++)
				/* analyze each argument; optimized branch */
			if (unlikely(syscall_desc[syscall_nr].map_args[i] > 0)) 
				/* sanity check -- probably non needed */
				if (likely(
				(void *)thread_ctx->syscall_ctx.arg[i] != NULL))
				/* 
				 * argument i is changed by the system call;
				 * the length of the change is given by
				 * map_args[i]
				 */
				tagmap_clrn(thread_ctx->syscall_ctx.arg[i],
					syscall_desc[syscall_nr].map_args[i]);
		}
	}
}

/*
 * trace inspection (instrumentation function)
 *
 * traverse the basic blocks (BBLs) on the trace and
 * inspect every instruction for instrumenting it
 * accordingly
 *
 * @trace:      instructions trace; given by PIN
 * @v:		callback value
 */
static void
trace_inspect(TRACE trace, VOID *v)
{
	/* iterators */
	BBL bbl;
	INS ins;
	xed_iclass_enum_t ins_indx;

	/* versioning support */
	ADDRINT version, version_mask = (ADDRINT)v;

	if (version_mask) {
		/*
		 * ignore code cache versions that we
		 * are not supposed to instrument
		 */
		version = TRACE_Version(trace);
		if ((version & version_mask) == 0)
			return;
	}

	/* traverse all the BBLs in the trace */
	for (bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
		/* traverse all the instructions in the BBL */
		for (ins = BBL_InsHead(bbl);
				INS_Valid(ins);
				ins = INS_Next(ins)) {
			        /*
				 * use XED to decode the instruction and
				 * extract its opcode
				 */
				ins_indx = (xed_iclass_enum_t)INS_Opcode(ins);

				/* 
				 * invoke the pre-ins instrumentation callback
				 */
				if (ins_desc[ins_indx].pre != NULL)
					ins_desc[ins_indx].pre(ins);

				/*
				 * analyze the instruction (default handler)
				 */
				if (ins_desc[ins_indx].dflact == INSDFL_ENABLE)
					ins_inspect(ins);

				/* 
				 * invoke the post-ins instrumentation callback
				 */
				if (ins_desc[ins_indx].post != NULL)
					ins_desc[ins_indx].post(ins);
		}
	}
}

/*
 * initialize thread contexts
 *
 * spill a tool register for the thread
 * contexts and register a thread start callback
 *
 * returns: 0 on success, 1 on error
 */
static inline int
thread_ctx_init(void)
{
	/* claim a tool register; optimized branch */
	if (unlikely(
		(thread_ctx_ptr = PIN_ClaimToolRegister()) == REG_INVALID())) {
		/* error message */
		LOG(string(__func__) + ": register claim failed\n");

		/* failed */
		return 1;
	}

	/* 
	 * thread start/stop hooks;
	 * keep track of the threads and allocate/free space for the
	 * per-thread logistics (i.e., syscall context, VCPU, etc)
	 */
	PIN_AddThreadStartFunction(thread_alloc, NULL);
	PIN_AddThreadFiniFunction(thread_free, NULL);

	/* success */
	return 0;
}

/*
 * FIXME: global handler for internal errors (i.e., errors from libdft)
 *
 * for unknown reasons, when an analysis function is executed,
 * the EFLAGS.AC bit (i.e., bit 18) is asserted, thus leading
 * into a runtime exception whenever an unaligned read/write
 * is performed from libdft. This callback can be registered
 * with PIN_AddInternalExceptionHandler() so as to trap the
 * generated signal and remediate
 *
 * @tid:		thread id
 * @pExceptInfo:	exception descriptor
 * @pPhysCtxt:		physical processor state
 * @v:			callback value
 */
static EXCEPT_HANDLING_RESULT
fix_eflags(THREADID tid, EXCEPTION_INFO *pExceptInfo,
		PHYSICAL_CONTEXT *pPhysCtxt, VOID *v)
{
	/* we only care about unaligned memory accesses */
	if (PIN_GetExceptionCode(pExceptInfo) ==
			EXCEPTCODE_ACCESS_MISALIGNED) {
		/* clear EFLAGS.AC */
		PIN_SetPhysicalContextReg(pPhysCtxt, REG_EFLAGS,
			CLEAR_EFLAGS_AC(PIN_GetPhysicalContextReg(pPhysCtxt,
					REG_EFLAGS)));
		
		/* the exception is handled gracefully; commence execution */
		return EHR_HANDLED;
	}
	else
		/* unknown exception; pass to the application */
		return EHR_UNHANDLED;
}


/*
 * outstream file for wrting compare offsets
 */
std::ofstream out;
int limit_offset;
int limit_lea;

/*
 * initialization of the core tagging engine;
 * it must be called before using everything else
 *
 * @version_mask:	mask to be applied to the code cache
 * 			versions that will be instrumented by
 * 			libdft (0 enables libdft permanently)
 *
 * returns: 0 on success, 1 on error
 */
int
libdft_init(ADDRINT version_mask)
{
	/* initialize thread contexts; optimized branch */
	if (unlikely(thread_ctx_init()))
		/* thread contexts failed */
		return 1;

	/* initialize the tagmap; optimized branch */
	if (unlikely(tagmap_alloc()))
		/* tagmap initialization failed */
		return 1;
       // string indexfile("../../../cmp.bin");
        //::remove(indexfile.c_str());
       // out.open(indexfile.c_str());
         
	/*
	 * syscall hooks; store the context of every syscall
	 * and invoke registered callbacks (if any)
	 */

	/* register sysenter_save() to be called before every syscall */
	PIN_AddSyscallEntryFunction(sysenter_save, NULL);
	
	/* register sysexit_save() to be called after every syscall */
	PIN_AddSyscallExitFunction(sysexit_save, NULL);
	
	/* initialize the ins descriptors */
	(void)memset(ins_desc, 0, sizeof(ins_desc));

	/* register trace_ins() to be called for every trace */
	TRACE_AddInstrumentFunction(trace_inspect, (VOID *)version_mask);

	/* FIXME: ugly hack for bypassing unaligned address checks */
	PIN_AddInternalExceptionHandler(fix_eflags, NULL);
        //out.close();
	/* success */
	return 0;
}

/*
 * stop the execution of the application inside the
 * tag-aware VM; the execution of the application
 * is not interrupted
 *
 * NOTE: it also performs the appropriate cleanup
 */
void
libdft_die(void)
{
	/* deallocate the resources needed for the tagmap */
	tagmap_free();

	/*
	 * detach Pin from the application;
	 * the application will continue to execute natively
	 */
	PIN_Detach();
}

/*
 * add a new pre-ins callback into an instruction descriptor
 *
 * @desc:	the ins descriptor
 * @pre:	function pointer to the pre-ins handler
 *
 * returns:	0 on success, 1 on error
 */
int
ins_set_pre(ins_desc_t *desc, void (* pre)(INS))
{
	/* sanity checks; optimized branch */
	if (unlikely((desc == NULL) | (pre == NULL)))
		/* return with failure */
		return 1;

	/* update the pre-ins callback */
	desc->pre = pre;

	/* success */
	return 0;
}

/*
 * add a new post-ins callback into an instruction descriptor
 *
 * @desc:	the ins descriptor
 * @post:	function pointer to the post-ins handler
 *
 * returns:	0 on success, 1 on error
 */
int
ins_set_post(ins_desc_t *desc, void (* post)(INS))
{
	/* sanity checks; optimized branch */
	if (unlikely((desc == NULL) | (post == NULL)))
		/* return with failure */
		return 1;

	/* update the post-ins callback */
	desc->post = post;

	/* success */
	return 0;
}

/*
 * remove the pre-ins callback from an instruction descriptor
 *
 * @desc:	the ins descriptor
 *
 * returns:	0 on success, 1 on error
 */
int
ins_clr_pre(ins_desc_t *desc)
{
	/* sanity check; optimized branch */
	if (unlikely(desc == NULL))
		/* return with failure */
		return 1;

	/* clear the pre-ins callback */
	desc->pre = NULL;

        /* return with success */
        return 0;
}

/*
 * remove the post-ins callback from an instruction descriptor
 *
 * @desc:	the ins descriptor
 *
 * returns:	0 on success, 1 on error
 */
int
ins_clr_post(ins_desc_t *desc)
{
	/* sanity check; optimized branch */
	if (unlikely(desc == NULL))
		/* return with failure */
		return 1;

	/* clear the post-ins callback */
	desc->post = NULL;

        /* return with success */
        return 0;
}

/*
 * set (enable/disable) the default action in an instruction descriptor
 *
 * @desc:       the ins descriptor
 *
 * returns:     0 on success, 1 on error
 */
int
ins_set_dflact(ins_desc_t *desc, size_t action)
{
	/* sanity checks */
	
	/* optimized branch */
	if (unlikely(desc == NULL))
		/* return with failure */
		return 1;

	switch (action) {
		/* valid actions */
		case INSDFL_ENABLE:
		case INSDFL_DISABLE:
			break;
		/* default handler */
		default:
			/* return with failure */
			return 1;
	}

	/* set the default action */
	desc->dflact = action;

        /* return with success */
        return 0;
}

/* 
 * REG-to-VCPU map;
 * get the register index in the VCPU structure
 * given a PIN register (32-bit regs)
 *
 * @reg:	the PIN register
 * returns:	the index of the register in the VCPU
 */
size_t
REG32_INDX(REG reg)
{
	/* result; for the 32-bit registers the mapping is easy */
	size_t indx = reg - (LEVEL_BASE::REG_EAX-GPR_EAX);
	
	/* 
	 * sanity check;
	 * unknown registers are mapped to the scratch
	 * register of the VCPU
	 */
	if (unlikely(indx > GPR_NUM))
		indx = GPR_NUM;
	
	/* return the index */
	return indx;	
}

/* 
 * REG-to-VCPU map;
 * get the register index in the VCPU structure
 * given a PIN register (16-bit regs)
 *
 * @reg:	the PIN register
 * returns:	the index of the register in the VCPU
 */
size_t
REG16_INDX(REG reg)
{
	/* 
	 * differentiate based on the register;
	 * we map the 16-bit registers to their 32-bit
	 * containers (e.g., AX -> EAX)
	 */
	switch (reg) {
		/* di */
		case REG_DI:
			return 0;
			/* not reached; safety */
			break;
		/* si */
		case REG_SI:
			return 1;
			/* not reached; safety */
			break;
		/* bp */
		case REG_BP:
			return 2;
			/* not reached; safety */
			break;
		/* sp */
		case REG_SP:
			return 3;
			/* not reached; safety */
			break;
		/* bx */
		case REG_BX:
			return 4;
			/* not reached; safety */
			break;
		/* dx */
		case REG_DX:
			return 5;
			/* not reached; safety */
			break;
		/* cx */
		case REG_CX:
			return 6;
			/* not reached; safety */
			break;
		/* ax */
		case REG_AX:
			return 7;
			/* not reached; safety */
			break;
		default:
			/* 
			 * paranoia;
			 * unknown 16-bit registers are mapped
			 * to the scratch register of the VCPU
			 */
			return 8;
	}
}

/* 
 * REG-to-VCPU map;
 * get the register index in the VCPU structure
 * given a PIN register (8-bit regs)
 *
 * @reg:	the PIN register
 * returns:	the index of the register in the VCPU
 */
size_t
REG8_INDX(REG reg)
{
	/* 
	 * differentiate based on the register;
	 * we map the 8-bit registers to their 32-bit
	 * containers (e.g., AH -> EAX)
	 */
	switch (reg) {
		/* ah/al */
		case REG_AH:
		case REG_AL:
			return 7;
			/* not reached; safety */
			break;
		/* ch/cl */
		case REG_CH:
		case REG_CL:
			return 6;
			/* not reached; safety */
			break;
		/* dh/dl */
		case REG_DH:
		case REG_DL:
			return 5;
			/* not reached; safety */
			break;
		/* bh/bl */
		case REG_BH:
		case REG_BL:
			return 4;
			/* not reached; safety */
			break;
		default:
			/* 
			 * paranoia;
			 * unknown 8-bit registers are mapped
			 * to the scratch register
			 */
			return 8;
	}
}
