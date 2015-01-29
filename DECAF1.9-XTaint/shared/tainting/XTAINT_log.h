/*
 * XTAINT_log.h
 *
 *      Author: mchen
 */

#include <stdio.h>


#ifndef XTAINT_LOG_H_
#define XTAINT_LOG_H_

#ifdef CONFIG_TCG_XTAINT

#define XTAINT_MAX_POOL_SIZE (8 * 1024 * 1024)
#define XTAINT_POOL_THRESHOLD (1024 * 1024)

extern uint8_t xtaint_pool[XTAINT_MAX_POOL_SIZE];
extern uint8_t *xtaint_ptr_cur_rcrd;
extern uint32_t xtaint_cur_pool_sz;

extern FILE *xtaint_fp;

extern void xtaint_flush_to_file(FILE *);

#endif /* CONFIG_TCG_XTAINT */
#endif /* XTAINT_LOG_H_ */
