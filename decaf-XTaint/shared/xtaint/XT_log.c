/*
 * XT_log.c
 *      Author: mchen
 */

#ifdef CONFIG_TCG_XTAINT
#include "qemu-common.h"
#include "DECAF_main.h"
#include "XT_log.h"
#include "XT_ir_propagate.h"

uint8_t xt_pool[XT_MAX_POOL_SIZE];
uint8_t *xt_ptr_curr_record = xt_pool;
uint32_t xt_curr_pool_sz = XT_POOL_THRESHOLD;

FILE *xt_log = NULL;

void xt_flush_file(FILE *xt_log) {
    uint8_t *i_ptr = xtaint_pool;
    uint8_t *func_mark_ptr;

    while (i_ptr < xtaint_ptr_cur_rcrd) {
        func_mark_ptr = i_ptr;
        if(*func_mark_ptr == X_CALL_MARK \
                || *func_mark_ptr == X_RET_MARK\
                || *func_mark_ptr == X_SIZE_BEGIN\
                || *func_mark_ptr == X_SIZE_END)
            goto func_mark;

        fprintf(xt_log, "%x\t", *i_ptr++);   // src_flag
        fprintf(xt_log, "%x\t", *(uint32_t *) i_ptr);    // src_addr
        i_ptr += 4;
        fprintf(xt_log, "%x\t", *(uint32_t *) i_ptr);    // src_val
        i_ptr += 4;

        func_mark_ptr = i_ptr;
        // if function mark, print newline
        if(*func_mark_ptr == X_CALL_MARK || *func_mark_ptr == X_RET_MARK )
            goto func_mark;

        fprintf(xt_log, "%x\t", *i_ptr++);   // des_flag
        fprintf(xt_log, "%x\t", *(uint32_t *) i_ptr);    // des_addr
        i_ptr += 4;
        fprintf(xt_log, "%x\t", *(uint32_t *) i_ptr);    // des_val
        i_ptr += 4;

        fprintf(xt_log, "\n");
        continue;

func_mark:
        fprintf(xt_log, "%x\t", *i_ptr++);   // src_flag
        fprintf(xt_log, "%x\t", *(uint32_t *) i_ptr);    // src_addr
        i_ptr += 4;
        fprintf(xt_log, "%x\t", *(uint32_t *) i_ptr);    // src_val
        i_ptr += 4;

        fprintf(xt_log, "\n");
    }
    fprintf(xt_log, "\n");
}

#endif /* CONFIG_TCG_XTAINT */

