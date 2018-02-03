#include <linux/init.h>     // Macros used to mark up functions e.g., __init __exit
#include <linux/module.h>   // Core header for loading LKMs into the kernel
#include <linux/kernel.h>   // Contains types, macros, functions for the kernel
#include <linux/moduleparam.h>

void getProcCpuid(void);
void getCrRegs(void);
void writeCr0(unsigned long val);
void getMSR(u32 msr, u32 *low, u32 *hi);
int wiser_main(void);
int vmxCheckSupport(int cmd);

#define CHKBIT(val, x) ((val>>x) & 0x1)

