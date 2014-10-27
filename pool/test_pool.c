/* **********************************************************************
 * File:	test_pool.c
 * Desc:	test the global memory pool for recording Qemu temporary
 * 			info.
 * **********************************************************************
 */ 
#include <stdlib.h>
#include <signal.h>
#include "pool.h"

char *fpath = "/home/mchen/Workspace_SUSE/XTaint/pool/record-10_27.txt";

void test_pool();
void clean(int signo);

int main(int argc, char *argv[]){
	if((fp = fopen(fpath, "wa") ) == NULL){
		fprintf(stderr, "fail to open file\n");
		exit(1);
	}
	test_pool();
	if(signal(SIGINT, clean) == NULL)
		fprintf(stderr, "fail to catch SIGINT\n");
	// fclose(fp);
	return 0;
}

void test_pool() {
	char *pool = create_pool();
	int i = 0;
	for ( ; ; ) {
		insrt_rcrd(i);
		i++;
	}
	// deletePool(pool);
}

void clean(int signo) {
	if(signo == SIGINT) {
		printf("catch SIGINT\n");
	}
	delete_pool(pool);
	fclose(fp);
	exit(0);
}
