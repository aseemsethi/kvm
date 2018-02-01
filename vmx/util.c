int getCpuid (unsigned int *eax, unsigned int *ebx,
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
int main(int argc, char **argv) {
	unsigned eax, ebx, ecx, edx;

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
