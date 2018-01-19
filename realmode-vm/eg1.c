#include "stdio.h"
#include "stdint.h"
#include "string.h"
#include "fcntl.h"
#include "linux/ioctl.h"
#include <sys/mman.h>
#include "linux/kvm.h"

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

main() 
{
int status, fd, version;
int vmfd, vcpufd;

fd = open("/dev/kvm", O_RDWR);

// Check if KVM version is 12
version = ioctl(fd, KVM_GET_API_VERSION, 0);
if (version != 12)
	errx(1, "KVM version incorrect %d", version);
else
	printf("KVM version: %d", version);

// Check if KVM Extension required to setup Guest Mem is present
status = ioctl(fd, KVM_CHECK_EXTENSION, KVM_CAP_USER_MEMORY);
if (!status)
	errx(1, "KVM_CAP_USER_MEM Extension not present");

// Setup the VM
vmfd = ioctl(fd, KVM_CREATE_VM, (unsigned long)0);
if (!vmfd)
	errx(1, "Unable to create VM");
else
	printf("\nVM created with KVM");

// Allocate a page aligned mem and copy our code into it
// The last 2 params are fd, offset and are set as -1,0 for ANON regions,
// that are not backed by a file.
void *mem=mmap(0, 0x1000, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
if (mem == MAP_FAILED) 
	errx(1, "Unable to allocate memory for VM");
else
	printf("\n...memory allocated");

// Copy our code into it
memcpy(mem, code, sizeof(code));

// Update the VM about the mmap-ed region above
struct kvm_userspace_memory_region region;
memset(&region, 0 , sizeof(region));
region.slot		= 0;
region.guest_phys_addr	= 0x1000;
region.memory_size	= 0x1000;
region.userspace_addr	= (uint64_t)mem;
status = ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &region);
if (status == -1)
	errx(1, "KVM_SET_USER_MEMORY_REGION failed");
else
	printf("\n...memory region informed to VM");

// Create a VCPU
vcpufd = ioctl(vmfd, KVM_CREATE_VCPU, (unsigned long)0);
if (status == -1)
	errx(1, "KVM_CREATE_VCPU failed");
else
	printf("\n...VCPU Created");

// Allocate memory for kvm_run data structure
int vcpu_run_size;
struct kvm_run *run;
vcpu_run_size = ioctl(fd, KVM_GET_VCPU_MMAP_SIZE, 0);
run = (struct kvm_run*)mmap(0, vcpu_run_size, PROT_READ|PROT_WRITE,
	MAP_SHARED, vcpufd, 0);
if (run == MAP_FAILED) 
	errx(1, "Unable to allocate kvm_run memory for VCPU");
else
	printf("\n...kvm_run memory allocated for vcpu");

// Setup Special Registers - struct kvm_sregs
// cs points to 0, and ip points to reset vector at 16 bytes below top of mem
// We zero the base and selector fields in segment descriptors
struct kvm_sregs sregs;
status = ioctl(vcpufd, KVM_GET_SREGS, &sregs);
if (status == -1) errx(1, "KVM_GET_SREGS failed");
else printf("\n...got sregs from vcpu");
sregs.cs.base=0;
sregs.cs.selector=0;
status = ioctl(vcpufd, KVM_SET_SREGS, &sregs);
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
status = ioctl(vcpufd, KVM_SET_REGS, &regs);
if (status == -1) errx(1, "KVM_SET_REGS failed");
else printf("\n...set regs into vcpu");


// Run the VCPU
while(1) {
	ioctl(vcpufd, KVM_RUN, 0);
	switch(run->exit_reason) {
	case KVM_EXIT_HLT:
		printf("\nKVM_EXIT_HLT: exit");
		return 0;
	case KVM_EXIT_IO:
		if (run->io.direction == KVM_EXIT_IO_OUT &&
		    run->io.size      == 1 &&
		    run->io.port      == 0x3f8 &&
		    run->io.count     == 1)
			printf("\nData: %s", (char*)run+run->io.data_offset);
		else
			printf("\nUnhandled KVM_EXIT_IO");
		break;
	case KVM_EXIT_FAIL_ENTRY:
		printf("\n KVM_EXIT_FAIL_ENTRY: hardware entry fail reason=%x",
		(unsigned long long)run->fail_entry.hardware_entry_failure_reason);
		return 1;
	case KVM_EXIT_INTERNAL_ERROR:
		printf("\nKVM_EXIT_INTERNAL_ERROR: suberror = %x",
		run->internal.suberror);
		return 1;
	}
}

// Cleanup
munmap(mem, 0x1000);
munmap(run, vcpu_run_size);
close(vcpufd);
close(vmfd);
close(fd);

return 0;
printf("\nKVM Example completed");
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
