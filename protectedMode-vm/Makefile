CC=gcc
CFLAGS=-I.
DEPS = mykvm.h
OBJ = kvm_eg.o kvm_utils.o paging_util.c payload.o

kvmp: $(OBJ)
	gcc -o $@ $^ $(CFLAGS)
%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

payload.o: payload.ld code32p.o
	$(LD) -T $< -o $@

