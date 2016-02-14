objects = xt_propagate.o xt_record.o xt_utils.o

CC := g++

xt_propagate : $(objects)
	$(CC) -o xt_propagate $(objects) -g 

xt_record.o : xt_record.cpp xt_record.h xt_flag.h xt_utils.h
	$(CC) -c xt_record.cpp -g

xt_utils.o : xt_utils.cpp xt_utils.h
	$(CC) -c xt_utils.cpp -g

clean :
	rm xt_propagate $(objects)
