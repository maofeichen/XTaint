/*
 * XT_log_ir.h
 *      Author: mchen
 */

#ifndef XT_LOG_IR_H_
#define XT_LOG_IR_H_

#ifdef CONFIG_TCG_XTAINT
#define NUM_BYTE_SAVE 0x12

/* encode for flag */
#define XT_BYTE 1
#define XT_WORD 2
#define XT_LONG 3
#define XT_QUAD 4
#define XT_BASE_ESP 0x4  // address is relative to esp
#define XT_BASE_EBP 0x8  // address is relative to ebp
#define XT_LD 0xc
#define XT_ST 0x10
/* handle specially for memory store with pointer as taint source */
#define XT_ST_POINTER 0x1c
#define XT_LD_POINTER 0x28
#define XT_INSN_CALL 0x14
#define XT_INSN_RET 0x18
#define XT_SIZE_BEGIN 0x20
#define XT_SIZE_END 0x24
#define XT_INSN_ADDR 0x32

#define TCG_MOV 0x33
#define TCG_QEMU_LD 0x34
#define TCG_QEMU_ST 0x35


extern int xt_enable_log_ir;
extern int xt_do_log_ir(Monitor *mon, const QDict *qdict, QObject **ret_data);

extern int xt_enable_debug;
extern int xt_do_debug(Monitor *mon, const QDict *qdict, QObject **ret_data);

extern int xt_encode_tcg_ir;

extern void XT_write_tmp();
extern void XT_write_mark();
#endif /* CONFIG_TCG_XTAINT */

#endif /* XT_LOG_IR_H_ */
