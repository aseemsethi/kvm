#include "wiser.h"

int wiser_main() {
	u32 low, hi, support;
	uint32_t vmcs_num_bytes;

	getProcCpuid();
	getCrRegs();
	getMSR(0x480, &low, &hi);
	vmcs_num_bytes  =  hi & 0xfff; // Bits 44:32
	printk("vmcs_num_bytes = 0x%x\n", vmcs_num_bytes);

	// check if proc has VMX support
	support = vmxCheckSupport(1);
	if (support ==1)
		printk("VMX supported by chipset\n");
	else
		printk("VMX not supported by chipset\n");
	
	// check if proc has EPT support
	support = vmxCheckSupportEPT();
	if (support ==1)
		printk("EPT supported by chipset\n");
	else
		printk("EPT not supported by chipset\n");
	return 0;
}
