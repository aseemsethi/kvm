#include "stdio.h"
#include "stdint.h"
#include "string.h"
#include "fcntl.h"
#include "linux/ioctl.h"
#include <sys/mman.h>
#include "linux/kvm.h"
#include <asm/bootparam.h>

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
	uint64_t guest_phys_addr;
} kvm;
