/* **********************************************************************
 * File:	pool.h
 * Desc:	maintain the global memory pool for recording Qemu temporary
 * 			info.
 * **********************************************************************
 */ 

#define MAX_POOL_SIZE (1024 * 1024)
#define POOL_THRESHOLD 1024

char *pool;

char *createPool();
void deletePool(char *); 
