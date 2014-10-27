/* **********************************************************************
 * File:	pool.h
 * Desc:	maintain the global memory pool for recording Qemu temporary
 * 			info.
 * **********************************************************************
 */ 

#define MAX_POOL_SIZE (32)
#define POOL_THRESHOLD 4

#include <stdio.h>

char *pool;
int *ptr_cur_rcrd;
int cur_pool_sz;

FILE *fp;

char *create_pool();
void insrt_rcrd(int rcrd);
void delete_pool(char *); 
