#include "dtracker_debug.H"

#include "libdft_api.h"
#include "pin.H"

VOID CheckMagicOnRead(VOID *ip, VOID *addr) {
	if (debug_gotmagic_backward(addr)) {
		LOG("DEBUG " DT_DBG_MAGIC " identified b-reading from " + ptrstr((char *)addr-DT_DBG_MAGICLEN+1) + "\n " + 
			"DEBUG " + tag_memrange_sprint((ADDRINT)addr-DT_DBG_MAGICLEN+1, DT_DBG_MAGICLEN) + "\n"
		);
	}
	else if (debug_gotmagic_forward(addr)) {
		LOG("DEBUG " DT_DBG_MAGIC " identified f-reading from " + ptrstr((char *)addr) + "\n " + 
			"DEBUG " + tag_memrange_sprint((ADDRINT)addr, DT_DBG_MAGICLEN) + "\n"
		);
	}
}

VOID CheckMagicOnWrite(VOID *ip, VOID *addr) {
	if (debug_gotmagic_backward(addr)) {
		LOG("DEBUG " DT_DBG_MAGIC " identified b-writing to " + ptrstr((char *)addr-DT_DBG_MAGICLEN+1) + "\n " +
			"DEBUG " + tag_memrange_sprint((ADDRINT)addr-DT_DBG_MAGICLEN+1, DT_DBG_MAGICLEN) + "\n"
		);
	}
	else if (debug_gotmagic_forward(addr)) {
		LOG("DEBUG " DT_DBG_MAGIC " identified f-writing to " + ptrstr((char *)addr) + "\n " + 
			"DEBUG " + tag_memrange_sprint((ADDRINT)addr, DT_DBG_MAGICLEN) + "\n"
		);
	}
}

VOID CheckMagicValue(INS ins, VOID *v) {
	UINT32 memOperands = INS_MemoryOperandCount(ins);
	for (UINT32 memOp = 0; memOp < memOperands; memOp++) {
		if (INS_MemoryOperandIsRead(ins, memOp)) {
			INS_InsertPredicatedCall(
				ins, IPOINT_BEFORE, (AFUNPTR)CheckMagicOnRead,
				IARG_INST_PTR,
				IARG_MEMORYOP_EA, memOp,
				IARG_END
			);
		}

		if (INS_MemoryOperandIsWritten(ins, memOp)) {
			INS_InsertPredicatedCall(
				ins, IPOINT_BEFORE, (AFUNPTR)CheckMagicOnWrite,
				IARG_INST_PTR,
				IARG_MEMORYOP_EA, memOp,
				IARG_END
			);
		}
	}
}

/* vim: set noet ts=4 sts=4 sw=4 ai : */
