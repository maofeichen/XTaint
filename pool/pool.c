/* **********************************************************************
 * File:	pool.c
 * Desc:	maintain the global memory pool for recording Qemu temporary
 * 			info.
 * **********************************************************************
 */ 

#include <stdio.h>
#include <stdlib.h>
#include "pool.h"

char *createPool(){
	if( (pool = malloc(sizeof(*pool) * MAX_POOL_SIZE) ) == NULL){
		fprintf(stderr, "fail to create pool\n");
		exit(1);
	}
	return pool;
}

void deletePool(char *pool){
	free(pool);
} 
