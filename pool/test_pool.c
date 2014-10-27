/* **********************************************************************
 * File:	test_pool.c
 * Desc:	test the global memory pool for recording Qemu temporary
 * 			info.
 * **********************************************************************
 */ 

#include "pool.h"

void test_pool();
int main(int argc, char *argv[]){
	test_pool();
	return 0;
}

void test_pool() {
	char *pool = createPool();
	deletePool(pool);
}
