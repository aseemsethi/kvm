#include "wiser.h"

/*
 * home computer: Model 7, Extended Model 1
 * Intel Core 2 Extreme processor, Intel Xeon, model 17h
 */

void getCpuid (unsigned int *eax, unsigned int *ebx,
		 unsigned int *ecx, unsigned int *edx) {
	// ecx is input and output
	asm volatile("cpuid"
		: "=a" (*eax), // outputs
		  "=b" (*ebx),
		  "=c" (*ecx),
		  "=d" (*edx)
		: "0" (*eax), "2" (*ecx));  // inputs - 0th index 
}

/* 
 * https://en.wikipedia.org/wiki/CPUID
 * The format of the information in EAX is as follows:
 * 3:0 – Stepping
 * 7:4 – Model
 * 11:8 – Family
 * Processory Type: 00: Original OEM, 01: OneDrive, 10: Dual proc, 11: Intel resvd 
 * 13:12 – Processor Type
 * 19:16 – Extended Model
 * 27:20 – Extended Family
 */
void getProcCpuid(void) {
	unsigned eax, ebx, ecx, edx;

	ecx = 0x0;
	eax = 1; // proc info
	getCpuid(&eax, &ebx, &ecx, &edx);
	printk("Stepping %d\n", eax & 0xF);
	printk("Model %d\n", (eax >> 4) & 0xF);
	printk("Family %d\n", (eax >> 12) & 0xF);
	printk("Processor Type %d\n", (eax >> 12) & 0x3);
	printk("Extended Model %d\n", (eax >> 16) & 0xF);
	printk("Extended Family %d\n", (eax >> 20) & 0xFF);

	eax = 3; // serial number
	getCpuid(&eax, &ebx, &ecx, &edx);
	printk("Serial Number 0x%08x%08x\n", edx, ecx);
}

/*
 * en.wikipedia.org/wiki/CPUID
 */
int vmxCheckSupport(int cmd) {
	unsigned eax, ebx, ecx, edx;

	ecx = 0x0;
	eax = cmd; // proc info
	getCpuid(&eax, &ebx, &ecx, &edx);
	if (CHKBIT(ecx, 5) == 1)
		return 1;
	else
		return 0;

}

/*
 * processor is in 32 bit mode here
 */
void writeCr0(unsigned long val) {
         asm volatile(
			"mov %0, %%cr0"
		: 
		:"r" (val)
		);
}

/*
 * READ MSRs// 30:00 VMCS revision id
 *  31:31 shadow VMCS indicator
 *  -----------------------------
 *  32:47 VMCS region size, 0 <= size <= 4096
 *  48:48 use 32-bit physical address, set when x86_64 disabled
 *  49:49 support of dual-monitor treatment of SMI and SMM
 *  53:50 memory type used for VMCS access
 *  54:54 logical processor reports information in the VM-exit 
 *        instruction-information field on VM exits due to
 *        execution of INS/OUTS
 *  55:55 set if any VMX controls that default to `1 may be
 *        cleared to `0, also indicates that IA32_VMX_TRUE_PINBASED_CTLS,
 *        IA32_VMX_TRUE_PROCBASED_CTLS, IA32_VMX_TRUE_EXIT_CTLS and
 *        IA32_VMX_TRUE_ENTRY_CTLS MSRs are supported.
 *  56:63 reserved, must be zero
 */
void getMSR(u32 msr, u32 *low, u32 *hi) {
	asm volatile("rdmsr" : "=a"(*low), "=d"(*hi) : "c"(msr));
	printk("msr=0x%x, hi=%x lo=%x\n", msr, *hi, *low);
}

int vmxCheckSupportEPT() {
	u32 low, hi;
	getMSR(IA32_VMX_PROCBASED_CTLS, &low, &hi);
	printk("MSR IA32_VMX_PROCBASED_CTLS: hi: %x, low: %x\n", hi, low);
	if (CHKBIT(hi, 31) == 1) { // 63rd bit should be 1
		getMSR(IA32_VMX_PROCBASED_CTLS2, &low, &hi);
		if (CHKBIT(hi, 2) == 1) // 33rd bit should be 1
			return 1;
	}
	return 0;
}
  
void getCrRegs(void) {
#ifdef __x86_64__
	u64 cr0, cr2, cr3;
	printk("x86_64 mode\n");
	asm volatile (
		"mov %%cr0, %%rax\n\t"
		"mov %%eax, %0\n\t"
		"mov %%cr2, %%rax\n\t"
		"mov %%eax, %1\n\t"
		"mov %%cr4, %%rax\n\t"
		"mov %%eax, %2\n\t"
	:	"=m" (cr0), "=m" (cr2), "=m" (cr3)
	:	/* no input */
	:	"%rax"
	);
#elif defined(__i386__)
	printk("x86 i386 mode\n");
	u32 cr0, cr2, cr3;
	printk("x86_64 mode\n");
	asm volatile (
		"mov %%cr0, %%eax\n\t"
		"mov %%eax, %0\n\t"
		"mov %%cr2, %%eax\n\t"
		"mov %%eax, %1\n\t"
		"mov %%cr4, %%eax\n\t"
		"mov %%eax, %2\n\t"
	:	"=m" (cr0), "=m" (cr2), "=m" (cr3)
	:	/* no input */
	:	"%eax"
	);
#endif
	printk("cr0 = 0x%llx\n", cr0);
	printk("cr2 = 0x%llx\n", cr2);
	printk("cr3 = 0x%llx\n", cr3);
}
