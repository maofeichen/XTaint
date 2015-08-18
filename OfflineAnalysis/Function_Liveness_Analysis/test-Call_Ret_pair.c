/* 
 * *****************************************************************************
 * file:	test-Call_Ret_pair.c
 * desc:	this file try to answer the question: is it true that the insn
 *				CALL and RET are always paired?
 *			By call simple functions, and check the assembly code, we will
 *				know that if CALL and RET are always paired.
 *	author:	mchen
 * *****************************************************************************
 */

#include <stdlib.h>
#include <stdio.h>

void foo1();
void foo2();
void foo3();

void foo1() {
	printf("foo1\n");
}

void foo2() {
	printf("foo2\n");
	foo3();
}

void foo3() {
	printf("foo3\n");
}

void main(void) {
	foo1();
	foo2();

//	return 0;
	exit(0);
}
