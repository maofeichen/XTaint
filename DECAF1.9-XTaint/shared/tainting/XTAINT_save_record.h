/*
 * XTAINT_save_record.h
 *
 *      Author: mchen
 */


#ifndef XTAINT_SAVE_RECORD_H_
#define XTAINT_SAVE_RECORD_H_
#ifdef CONFIG_TCG_XTAINT

#define NUM_BYTE_SAVE 0x12

/* encode for flag */
#define X_BYTE 0x1
#define X_WORD 0x2
#define X_LONG 0x3
#define X_QUAD 0x4
#define X_BASE_ESP 0x4	// address is relative to esp
#define X_BASE_EBP 0x8	// address is relative to ebp
#define X_LD 0xc
#define X_ST 0x10
#define X_CALL_MARK 0x14
#define X_RET_MARK 0x18
/* handle specially for memory store with pointer as taint source */
#define X_ST_POINTER 0x1c
#define X_SIZE_BEGIN 0x20
#define X_SIZE_END 0x24
#define X_DEBUG 0x80

extern int xtaint_save_temp_enabled;

/* helper functions of saving record */
//extern void XTAINT_save_mem_st();

#endif /* CONFIG_TCG_XTAINT */
#endif /* XTAINT_SAVE_RECORD_H_ */

