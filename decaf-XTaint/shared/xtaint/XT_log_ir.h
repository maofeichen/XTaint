/*
 * XT_log_ir.h
 *      Author: mchen
 */

#ifndef XT_LOG_IR_H_
#define XT_LOG_IR_H_

#ifdef CONFIG_TCG_XTAINT
#define NUM_BYTE_SAVE 0x12

/* encode for flag */
#define X_BYTE 0x1
#define X_WORD 0x2
#define X_LONG 0x3
#define X_QUAD 0x4
#define XT_BASE_ESP 0x4  // address is relative to esp
#define XT_BASE_EBP 0x8  // address is relative to ebp
#define XT_LD 0xc
#define XT_ST 0x10
#define X_CALL_MARK 0x14
#define X_RET_MARK 0x18
/* handle specially for memory store with pointer as taint source */
#define X_ST_POINTER 0x1c
#define X_SIZE_BEGIN 0x20
#define X_SIZE_END 0x24
#define X_LD_POINTER 0x28
#define X_DEBUG 0x80

extern int xt_enable_log_ir;

extern int xt_do_log_ir(Monitor *mon, const QDict *qdict, QObject **ret_data);

extern void XT_write_tmp();
#endif /* CONFIG_TCG_XTAINT */

#endif /* XT_LOG_IR_H_ */
