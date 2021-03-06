#include "stdio.h"
#include "stdint.h"
#include "string.h"
#include "fcntl.h"
#include "linux/ioctl.h"
#include <sys/mman.h>
#include "linux/kvm.h"
#include <asm/bootparam.h>

/*
[asethi@localhost kvm_example]$ ./a.out 
KVM version: 12
VM created with KVM
...memory allocated
...memory region informed to VM
...VCPU Created
...kvm_run memory allocated for vcpu
...got sregs from vcpu
...set cs sregs into vcpu
...set regs into vcpu
Data: 4
Data: 
*/

//#define BZ_KERNEL_START	0x100000UL
#define BZ_KERNEL_START	0x10000UL
#define BOOT_PROTOCOL_REQUIRED	0x206
static const char *BZIMAGE_MAGIC = "HdrS";

/*
 * Machine code to run inside a VM
 */
const uint8_t code[] = {
0xba, 0xf8, 0x03, // mov $0x3f8, %dx
0x00, 0xd8,       // add %bl, %al
0x04, '0',        // add $'0', %al
0xee,             // out %al, (%dx)
0xb0, '\n',       // mov $'\n', %al
0xee,             // out %al, (%dx)
0xf4              // hlt
};

struct kvm {
	int fd;
	int sysfd;
	int vmfd;
	int vcpufd;
	int vcpu_run_size;
	struct kvm_run *run;

	const char* kernelFileName;

	char*	userspace_addr;
	uint64_t guest_phys_addr;
};

void *guest_addr_to_host(struct kvm* kvm, uint64_t offset) {
	void *addr = kvm->userspace_addr + (offset - kvm->guest_phys_addr);

	return addr;
}

/*
 * Kernel Image
 * A bZimage file consist of bootsect.o, setup.o, misc.o and piggy.o files.
 * The original vmlinux kernel image compressed in piggy.o file.
 * piggy.o contains the gzipped vmlinux file in its data section (ELF)
 */
int loadBzImage(struct kvm *kvm) {
	struct boot_params boot;
	void *p;
	int nr;

	read(kvm->fd, &boot, sizeof(boot));
	if (memcmp(&boot.hdr.header, BZIMAGE_MAGIC, strlen(BZIMAGE_MAGIC)) != 0) {
		printf("\n BZIMAGE_MAGIC not found");
		return 0;
	}
	printf("\nKernel File:  bzimage magic found");

	if (boot.hdr.version < BOOT_PROTOCOL_REQUIRED)
		errx("Too old kernel");
	printf("\n  boot.hdr.version: %d", boot.hdr.version);

	/* read actual kernel image (vmlinux.bin) to BZ_KERNEL_START */
	lseek(kvm->fd, 0, SEEK_SET);
	lseek(kvm->fd, (boot.hdr.setup_sects+1) * 512, SEEK_SET);

	// copy vmlinux.bin to BZ_KERNEL_START
	p = guest_addr_to_host(kvm, BZ_KERNEL_START);
	printf("\n Reading kernel image into host vadr %x: ", (uint64_t)p);
/*
	while ((nr == read(kvm->fd, p, 65536)) > 0) {
		printf("!");
		p += nr;
	}
*/

	return boot.hdr.code32_start;
}

kvm_init(struct kvm *kvm) {
	int status, version;

	kvm->sysfd = open("/dev/kvm", O_RDWR);
	// Check if KVM version is 12
	version = ioctl(kvm->sysfd, KVM_GET_API_VERSION, 0);
	if (version != 12)
		errx(1, "KVM version incorrect %d", version);
	else
		printf("\nKVM version: %d", version);

	// Check if KVM Extension required to setup Guest Mem is present
	status = ioctl(kvm->sysfd, KVM_CHECK_EXTENSION, KVM_CAP_USER_MEMORY);
	if (!status)
		errx(1, "KVM_CAP_USER_MEM Extension not present");

	// Setup the VM
	kvm->vmfd = ioctl(kvm->sysfd, KVM_CREATE_VM, (unsigned long)0);
	if (!kvm->vmfd)
		errx(1, "Unable to create VM");
	else
		printf("\nVM created with KVM");

	return 1;
}

kvm_alloc_mem(struct kvm *kvm) {
	int	status;

	// Allocate a page aligned mem and copy our code into it
	// The last 2 params are fd, offset and are set as -1,0 for ANON regions,
	// that are not backed by a file.
	kvm->userspace_addr=mmap(0, 0x1000, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
	if (kvm->userspace_addr == MAP_FAILED) 
		errx(1, "Unable to allocate memory for VM");
	else
		printf("\n...memory allocated at userspace_mem:%x", (uint64_t)kvm->userspace_addr);

	kvm->guest_phys_addr = 0x1000;

	// Copy our code into it
	memcpy(kvm->userspace_addr, code, sizeof(code));
	/*
  	status = loadBzImage(kvm);
	if (status == 0)
		errx("Not a valid kernel image");
	*/

	// Update the VM about the mmap-ed region above
	struct kvm_userspace_memory_region region;
	memset(&region, 0 , sizeof(region));
	region.slot		= 0;
	region.guest_phys_addr	= kvm->guest_phys_addr;
	region.memory_size	= 0x1000;  // Set the guest mem to 16 megs for now
	region.userspace_addr	= (uint64_t)kvm->userspace_addr;
	status = ioctl(kvm->vmfd, KVM_SET_USER_MEMORY_REGION, &region);
	if (status == -1)
		errx(1, "KVM_SET_USER_MEMORY_REGION failed");
	else
		printf("\n...memory region informed to VM");
	return 0;
}

kvm_init_cpu (struct kvm *kvm) {
	int status;

	// Create a VCPU
	kvm->vcpufd = ioctl(kvm->vmfd, KVM_CREATE_VCPU, (unsigned long)0);
	if (status == -1)
		errx(1, "KVM_CREATE_VCPU failed");
	else
		printf("\n...VCPU Created");

	// Allocate memory for kvm_run data structure
	kvm->vcpu_run_size = ioctl(kvm->sysfd, KVM_GET_VCPU_MMAP_SIZE, 0);
	kvm->run = (struct kvm_run*)mmap(0, kvm->vcpu_run_size, PROT_READ|PROT_WRITE,
		MAP_SHARED, kvm->vcpufd, 0);
	if (kvm->run == MAP_FAILED) 
		errx(1, "Unable to allocate kvm_run memory for VCPU");
	else
		printf("\n...kvm_run memory allocated for vcpu");

	// Setup Special Registers - struct kvm_sregs
	// cs points to 0, and ip points to reset vector at 16 bytes below top of mem
	// We zero the base and selector fields in segment descriptors
	struct kvm_sregs sregs;
	status = ioctl(kvm->vcpufd, KVM_GET_SREGS, &sregs);
	if (status == -1) errx(1, "KVM_GET_SREGS failed");
	else printf("\n...got sregs from vcpu");
	sregs.cs.base=0;
	sregs.cs.selector=0;
	status = ioctl(kvm->vcpufd, KVM_SET_SREGS, &sregs);
	if (status == -1) errx(1, "KVM_SET_SREGS failed");
	else printf("\n...set cs sregs into vcpu");

	// Setup Standard Registers - struct kvm_regs
	// We set all regs to 0, ip points to our code at 0x1000, relative to 0x0,
	// our addends 2 and 2, and initial flags at 2
	struct kvm_regs regs;
	memset(&regs, 0, sizeof(regs));
	regs.rip = 0x1000;
	regs.rax = 2;
	regs.rbx = 2;
	regs.rflags = 0x2;
	status = ioctl(kvm->vcpufd, KVM_SET_REGS, &regs);
	if (status == -1) errx(1, "KVM_SET_REGS failed");
	else printf("\n...set regs into vcpu");
}

kvm_run(struct kvm *kvm) {
	// Run the VCPU
	while(1) {
		ioctl(kvm->vcpufd, KVM_RUN, 0);
		switch(kvm->run->exit_reason) {
		case KVM_EXIT_HLT:
			printf("\nKVM_EXIT_HLT: exit");
			return 0;
		case KVM_EXIT_IO:
			if (kvm->run->io.direction == KVM_EXIT_IO_OUT &&
			    kvm->run->io.size      == 1 &&
			    kvm->run->io.port      == 0x3f8 &&
			    kvm->run->io.count     == 1)
				printf("\nData: %s", (char*)kvm->run+kvm->run->io.data_offset);
			else
				printf("\nUnhandled KVM_EXIT_IO");
			break;
		case KVM_EXIT_FAIL_ENTRY:
			printf("\n KVM_EXIT_FAIL_ENTRY: hardware entry fail reason=%x",
			(unsigned long long)kvm->run->fail_entry.hardware_entry_failure_reason);
			return 1;
		case KVM_EXIT_INTERNAL_ERROR:
			printf("\nKVM_EXIT_INTERNAL_ERROR: suberror = %x",
			kvm->run->internal.suberror);
			return 1;
		}
	}

	// Cleanup
	munmap(kvm->userspace_addr, 0x1000);
	munmap(kvm->run, kvm->vcpu_run_size);
	close(kvm->vcpufd);
	close(kvm->vmfd);
	close(kvm->sysfd);

	return 0;
	printf("\nKVM Example completed");
}

main(int argc, char* argv[]) 
{
	struct kvm kvm;
	int status;

	if (argc < 2)
		errx("Usage: a.out kernelFileName");
	kvm.kernelFileName = argv[1];

	kvm.fd = open(kvm.kernelFileName, O_RDONLY);
	if (kvm.fd < 0)
		errx("could not open kernel image");

	kvm_init(&kvm);
	kvm_alloc_mem(&kvm);
	kvm_init_cpu(&kvm);
	kvm_run(&kvm);
}

/*
Tracing Events - while the a.out runs gives us the following traces
$echo 1 >/sys/kernel/debug/tracing/events/kvm/enable
$cat /sys/kernel/debug/tracing/trace_pipe > trace
$echo 0 >/sys/kernel/debug/tracing/events/kvm/enable

$cat trace
           a.out-20024 [001] .... 2323301.150469: kvm_update_master_clock: masterclock 0 hostclock tsc offsetmatched 0
           a.out-20024 [001] d... 2323301.154551: kvm_write_tsc_offset: vcpu=0 prev=0 next=18439928704022336791
           a.out-20024 [001] .... 2323301.154555: kvm_track_tsc: vcpu_id 0 masterclock 0 offsetmatched 0 nr_online 1 hostclock tsc
           a.out-20024 [001] .... 2323301.154902: kvm_update_master_clock: masterclock 1 hostclock tsc offsetmatched 1
           a.out-20024 [001] .... 2323301.154933: kvm_fpu: load
           a.out-20024 [001] d... 2323301.154934: kvm_entry: vcpu 0
           a.out-20024 [001] .... 2323301.154940: kvm_exit: reason EXCEPTION_NMI rip 0x1000 info 1000 80000b0e
           a.out-20024 [001] .... 2323301.154942: kvm_page_fault: address 1000 error_code 14
           a.out-20024 [001] d... 2323301.154952: kvm_entry: vcpu 0
           a.out-20024 [001] .... 2323301.154954: kvm_exit: reason EXCEPTION_NMI rip 0x1007 info 66 80000b0e
           a.out-20024 [001] .... 2323301.154955: kvm_page_fault: address 66 error_code 0
           a.out-20024 [001] .... 2323301.154963: kvm_emulate_insn: 0:1007:ee (real)
           a.out-20024 [001] d... 2323301.154964: kvm_entry: vcpu 0
           a.out-20024 [001] .... 2323301.154966: kvm_exit: reason EXCEPTION_NMI rip 0x1007 info 66 80000b0e
           a.out-20024 [001] .... 2323301.154967: kvm_page_fault: address 66 error_code 9
           a.out-20024 [001] .... 2323301.154968: kvm_emulate_insn: 0:1007:ee (real)
           a.out-20024 [001] .... 2323301.154971: kvm_pio: pio_write at 0x3f8 size 1 count 1 val 0x34 
           a.out-20024 [001] .... 2323301.154974: kvm_userspace_exit: reason KVM_EXIT_IO (2)
           a.out-20024 [001] .... 2323301.154976: kvm_fpu: unload
           a.out-20024 [001] d... 2323301.155001: kvm_entry: vcpu 0
           a.out-20024 [001] .... 2323301.155004: kvm_exit: reason EXCEPTION_NMI rip 0x100a info 66 80000b0e
           a.out-20024 [001] .... 2323301.155004: kvm_page_fault: address 66 error_code 9
           a.out-20024 [001] .... 2323301.155007: kvm_emulate_insn: 0:100a:ee (real)
           a.out-20024 [001] .... 2323301.155007: kvm_pio: pio_write at 0x3f8 size 1 count 1 val 0xa 
           a.out-20024 [001] .... 2323301.155008: kvm_userspace_exit: reason KVM_EXIT_IO (2)
           a.out-20024 [001] d... 2323301.155033: kvm_entry: vcpu 0
           a.out-20024 [001] .... 2323301.155036: kvm_exit: reason EXCEPTION_NMI rip 0x100b info 0 80000b0d
           a.out-20024 [001] .... 2323301.155038: kvm_emulate_insn: 0:100b:f4 (real)
           a.out-20024 [001] .... 2323301.155040: kvm_userspace_exit: reason KVM_EXIT_HLT (5)

*/


/*
[root@localhost xinetd.d]# perf stat -e 'kvm:*' -a sleep 10
 Performance counter stats for 'system wide':
                 5      kvm:kvm_entry                                 
                 2      kvm:kvm_pio                                  
                 5      kvm:kvm_exit                                 
                 4      kvm:kvm_page_fault                            
                 4      kvm:kvm_emulate_insn                          
                 1      kvm:kvm_write_tsc_offset                      
                 2      kvm:kvm_update_master_clock                  
                 1      kvm:kvm_track_tsc                             
                 3      kvm:kvm_userspace_exit                        
                 2      kvm:kvm_fpu                                  

*/
