#include <stdio.h>  // for printf(), perror() 
#include <fcntl.h>  // for open() 
#include <stdlib.h> // for exit() 
#include <string.h> // for memcpy()
#include <sys/mman.h>   // for mmap()
#include <sys/ioctl.h>  // for ioctl()

typedef struct  {
        unsigned int    eip;
        unsigned int    eflags;
        unsigned int    eax;
        unsigned int    ecx;
        unsigned int    edx;
        unsigned int    ebx;
        unsigned int    esp;
        unsigned int    ebp;
        unsigned int    esi;
        unsigned int    edi;
        unsigned int     es;
        unsigned int     cs;
        unsigned int     ss;
        unsigned int     ds;
        unsigned int     fs;
        unsigned int     gs;
} regs_ia32;

regs_ia32   vm;
char devname[] = "/dev/wiser";

int main( int argc, char **argv )
{
    int* addr;

    // open the virtual-machine device-file
	int fd = open( devname, O_RDWR );
	if ( fd < 0 ) { perror( devname ); exit(1); }

	// mmap the legacy 8086 memory area
	// mmap() creates a new mapping in the virtual address space of the 
	// calling process. Get the virtaddr of 0x0. 
	// The starting address for mapping is specified in 1st param 'addr'.
	// Note that we are trying to map all of the 1M in the user virtual 
	// address space from 0x0 onwards. That way, we can refer directly 
	// to address like (0x11 << 2) which belongs to the first 256 bytes
	// of memory where IVT sits.
	int size = 0x110000;
	addr = mmap((void*)0, size, PROT_READ|PROT_WRITE, 
					MAP_FIXED|MAP_SHARED, fd, 0);
	if (addr == MAP_FAILED) {
		perror("mmap"); exit(1);
	}

	// get the vector for the desired interrupt
	unsigned int interrupt_number = 0x11;
	unsigned int vector = *(unsigned int*)(interrupt_number << 2);
	// Show the selected interrupt vector
	printf("interrupt- 0x%02X\n", interrupt_number);
	printf("vector=%08X\n", vector);

	// plant the 'return' stack and code
	// tos - top of stack, i.e. 0x8000
	unsigned short *tos = (unsigned short*)0x8000;
	// eoi - end of interrupt, IP pointer
	unsigned int *eoi = (unsigned int*)0x8000;
	eoi[0] = 0x90C1010F;	// 'vmcall' instruction
	// setup the top 3 entries in the stack, ending with the IP ptr
	tos[-1] = 0x0000;  // image of FLAGS
	tos[-2] = 0x0000;  // image of CS
	tos[-3] = 0x8000;  // IP points to the 'vmcall'

	// Initialize regiser fields needed for our test
	vm.eflags = 0x00023000;
	vm.eip = vector & 0xFFFF;  // this points to the interrupt handler
	vm.cs = (vector >> 16);
	vm.esp = 0x7FFA;  // 6 bytes below top of stack, since we have 3 entries
	vm.ss = 0x0000;

	// put some recognizable fields in other regs
    vm.eax  = 0xAAAAAAAA;
    vm.ebx  = 0xBBBBBBBB;
    vm.ecx  = 0xCCCCCCCC;
    vm.edx  = 0xDDDDDDDD;
    vm.ebp  = 0xBBBBBBBB;
    vm.esi  = 0xCCCCCCCC;
    vm.edi  = 0xDDDDDDDD;
    vm.ds   = 0xDDDD;
    vm.es   = 0xEEEE;
    vm.fs   = 0x8888;
    vm.gs   = 0x9999;

    // invoke the virtual-machine
	int retval = ioctl( fd, sizeof( vm ), &vm );

	// display the register-values on return from the VMM
	    printf( "\nretval = %-3d ", retval );
    printf( "EIP=%08X ", vm.eip );
    printf( "EFLAGS=%08X ", vm.eflags );

    printf( "\n" );
    printf( "EAX=%08X ", vm.eax );
    printf( "EBX=%08X ", vm.ebx );
    printf( "ECX=%08X ", vm.ecx );
    printf( "EDX=%08X ", vm.edx );
    printf( "CS=%04X ", vm.cs );
    printf( "DS=%04X ", vm.ds );
    printf( "FS=%04X ", vm.fs );

    printf( "\n" );
    printf( "ESP=%08X ", vm.esp );
    printf( "EBP=%08X ", vm.ebp );
    printf( "ESI=%08X ", vm.esi );
    printf( "EDI=%08X ", vm.edi );
    printf( "SS=%04X ", vm.ss );
    printf( "ES=%04X ", vm.es );
    printf( "GS=%04X ", vm.gs );

    printf( "\n" );
}

