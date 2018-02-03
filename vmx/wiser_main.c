#include "wiser.h"

int wiser_main() {
	u32 low, hi, support;

	getProcCpuid();
	getCrRegs();
	getMSR(0x480, &low, &hi);

	// check if proc has VMX support
	support = vmxCheckSupport(1);
	if (support ==1)
		printk("VX supported by chipset\n");
	else
		printk("VX supported by chipset\n");
	return 0;
}
