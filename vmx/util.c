#include "wiser.h"

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
 * READ MSRs
 */
void getMSR(u32 msr, u32 *low, u32 *hi) {
	uint32_t vmcs_num_bytes;

	asm volatile("rdmsr" : "=a"(*low), "=d"(*hi) : "c"(msr));
	printk("msr=0x%x, hi=%x lo=%x\n", msr, *hi, *low);
	vmcs_num_bytes  =  (msr >> 32 ) & 0xfff; // Bits 44:32
	printk("vmcs_num_bytes = 0x%x", vmcs_num_bytes);
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
