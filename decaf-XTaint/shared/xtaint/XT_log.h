/*
 * XT_log.h
 *      Author: mchen
 */

#ifndef XT_LOG_H_
#define XT_LOG_H_
#ifdef CONFIG_TCG_XTAINT

#define XT_MAX_POOL_SIZE (8 * 1024 * 1024)
#define XT_POOL_THRESHOLD (1024 * 1024)

extern uint8_t xt_pool[XT_MAX_POOL_SIZE];
extern uint8_t *xt_ptr_curr_record;
extern uint32_t xt_curr_pool_sz;

extern FILE *xt_log;

extern void xt_flush_file(FILE *);

#endif /* CONFIG_TCG_XTAINT */
#endif /* XT_LOG_H_ */
