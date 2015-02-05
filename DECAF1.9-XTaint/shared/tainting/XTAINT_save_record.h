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
#define X_BYTE 0x0
#define X_WORD 0x1
#define X_LONG 0x2
#define X_QUAD 0x3
#define X_BASE_ESP 0x4
#define X_BASE_EBP 0x8
#define X_LD 0x10
#define X_ST 0x20
/* handle specially for memory store with pointer as taint source */
#define X_ST_POINTER 0x30
#define X_DEBUG 0x40

extern int xtaint_save_temp_enabled;

/* helper functions of saving record */
//extern void XTAINT_save_mem_st();

#endif /* CONFIG_TCG_XTAINT */
#endif /* XTAINT_SAVE_RECORD_H_ */

