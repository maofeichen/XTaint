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
#define XT_INSN_CALL_SEC 0x4b
#define XT_INSN_RET 0x18
#define XT_INSN_RET_SEC 0x4c
#define XT_INSN_CALL_FF2_01 0x4e // call insn ff/2 encode first instrument
#define XT_INSN_CALL_FF2 0x4d
#define XT_SIZE_BEGIN 0x20
#define XT_SIZE_END 0x24
#define XT_INSN_ADDR 0x32
#define XT_TCG_DEPOSIT 0x4a

#define TCG_MOV 0x33
#define TCG_QEMU_LD 0x34
#define TCG_QEMU_ST 0x35
#define TCG_SHL 0x36
#define TCG_SHR 0x37
#define TCG_SAR 0x38
#define TCG_ROTL 0x39
#define TCG_ROTR 0x3a
#define TCG_ADD 0x3b
#define TCG_SUB 0x3c
#define TCG_MUL 0x3d
#define TCG_AND 0x3e
#define TCG_OR 0x3f
#define TCG_XOR 0x40
#define TCG_DIV 0x41
#define TCG_EXT8S 0x42
#define TCG_EXT16S 0x43
#define TCG_EXT8U 0x44
#define TCG_EXT16U 0x45
#define TCG_BSWAP16 0x46
#define TCG_BSWAP32 0x47
#define TCG_NOT 0x48
#define TCG_DEPOSIT 0x49

/* encode global temps*/
#define G_TEMP_ENV 0xFFF0
#define G_TEMP_CC_OP 0xFFF1
#define G_TEMP_CC_SRC 0xFFF2
#define G_TEMP_CC_DST 0xFFF3
#define G_TEMP_CC_TMP 0xFFF4
#define G_TEMP_EAX 0xFFF5
#define G_TEMP_ECX 0xFFF6
#define G_TEMP_EDX 0xFFF7
#define G_TEMP_EBX 0xFFF8
#define G_TEMP_ESP 0xFFF9
#define G_TEMP_EBP 0xFFFa
#define G_TEMP_ESI 0xFFFb
#define G_TEMP_EDI 0xFFFc



extern int xt_enable_log_ir;
extern int xt_do_log_ir(Monitor *mon, const QDict *qdict, QObject **ret_data);

extern int xt_enable_debug;
extern int xt_do_debug(Monitor *mon, const QDict *qdict, QObject **ret_data);

extern int xt_encode_tcg_ir;

extern int xt_enable_size_mark;
extern int xt_do_size_mark(Monitor *mon, const QDict *qdict, QObject **ret_data);

extern int xt_enable_func_call_mark;
extern int xt_do_func_call_mark(Monitor *mon, const QDict *qdict, QObject **ret_data);

extern void XT_write_tmp();
extern void XT_write_mark();
#endif /* CONFIG_TCG_XTAINT */

#endif /* XT_LOG_IR_H_ */
