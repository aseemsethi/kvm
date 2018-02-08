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
    // open the virtual-machine device-file
	int fd = open( devname, O_RDWR );
	if ( fd < 0 ) { perror( devname ); exit(1); }

	// mmap the legacy 8086 memory area
	int size = 0x110000;
	if (mmap((void*)0, size, PROT_READ|PROT_WRITE, 
			MAP_FIXED|MAP_SHARED, fd, 0) == MAP_FAILED) {
		perror("mmap"); exit(1);
	}

    // invoke the virtual-machine
	int retval = ioctl( fd, sizeof( vm ), &vm );
}

