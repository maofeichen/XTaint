/*
 * XTAINT_disp_taint.h
 *
 *  Created on: Jan 18, 2015
 *      Author: mchen
 */

#ifndef XTAINT_DISP_TAINT_H_
#define XTAINT_DISP_TAINT_H_
#ifdef CONFIG_TCG_XTAINT

/*
 * DECAF does not save memory info (virtual memory addr, size) in the shadow
 * memory page table.
 * To show what virtual memory are tainted, save these info in the shadow
 * memory page table additionally.
 */

typedef struct _XTAINT_vir_mem_info {
	uint32_t gva;
	uint8_t size;
} XTAINT_vir_mem_info;
#endif /* CONFIG_TCG_XTAINT */
#endif /* XTAINT_DISP_TAINT_H_ */
