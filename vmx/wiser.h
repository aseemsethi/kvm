#include <linux/init.h>     // Macros used to mark up functions e.g., __init __exit
#include <linux/module.h>   // Core header for loading LKMs into the kernel
#include <linux/kernel.h>   // Contains types, macros, functions for the kernel
#include <linux/moduleparam.h>

void getProcCpuid(void);
void getCrRegs(void);
