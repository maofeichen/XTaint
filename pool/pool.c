/* **********************************************************************
 * File:	pool.c
 * Desc:	maintain the global memory pool for recording Qemu temporary
 * 			info.
 * **********************************************************************
 */ 

#include <stdio.h>
#include <stdlib.h>
#include "pool.h"

void flush_to_file(FILE *);

char *create_pool(){
	if( (pool = malloc(sizeof(*pool) * MAX_POOL_SIZE) ) == NULL){
		fprintf(stderr, "fail to create pool\n");
		exit(1);
	}
	ptr_cur_rcrd = (int *)pool;
	cur_pool_sz = MAX_POOL_SIZE;
	return pool;
}

void insrt_rcrd(int rcrd){
	*ptr_cur_rcrd = rcrd;
	ptr_cur_rcrd += 1;
	cur_pool_sz -= 4;
	if(cur_pool_sz < POOL_THRESHOLD) {
		printf("threshold hit\n");
		flush_to_file(fp);
		ptr_cur_rcrd = (int *)pool;
		cur_pool_sz = MAX_POOL_SIZE;
	}
}

void delete_pool(char *pool){
	free(pool);
}

void flush_to_file(FILE *fp) {
	int *i_ptr;
	int icount = 0;

	for(i_ptr = (int *)pool; i_ptr < ptr_cur_rcrd; i_ptr++) {
		fprintf(fp, "%x\t", *i_ptr);
		icount++;
		if(icount % 6 == 0)
			fprintf(fp, "\n");

	}
	fprintf(fp, "\n");
} 
