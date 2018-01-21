#include "stdio.h"
#include "stdint.h"
#include "string.h"
#include "fcntl.h"
#include "linux/ioctl.h"
#include <sys/mman.h>
#include "linux/kvm.h"
#include <asm/bootparam.h>

#define REALMODE 0
#define PROTMODE 1

typedef struct kvm_t {
	int fd;
	int sysfd;
	int vmfd;
	int vcpufd;
	int vcpu_run_size;
	struct kvm_run *run;

	// CLI options
	const char* mode;
	const char* kernelFileName;

	char*	userspace_addr;
	int	guestmem_size;
	int	guest_phys_start;
} kvm;
