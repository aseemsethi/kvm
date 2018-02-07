#include <linux/init.h>     // Macros used to mark up functions e.g., __init __exit
#include <linux/module.h>   // Core header for loading LKMs into the kernel
#include <linux/kernel.h>   // Contains types, macros, functions for the kernel
#include <linux/moduleparam.h>

void getProcCpuid(void);
void getCrRegs(void);
void writeCr0(unsigned long val);
void getMSR(u32 msr, u32 *low, u32 *hi);
int wiser_main(void);
int wiser_exit(void);
int checkProcessor(void);
int vmxCheckSupport(int cmd);
int vmxCheckSupportEPT(void);
void setCr4Vmxe(void*);
void clearCr4Vmxe(void*);
void assignAddresses(void);

#define CHKBIT(val, x) ((val>>x) & 0x1)

// VMX CAPABILITY MSRs
#define IA32_VMX_BASIC 0x480

// Capability Reporting Reg of Pin-based VM-execution Controls (R/O)
// asynchronous events/interrupts
// One 32-bit value that controls asynchronous events in VMX non-root
// External-interrupt exiting (bit 0)
// Non maskable interrupt (NMI) exiting (bit 3)
// Virtual NMIs (bit 5)
// VMX preemption timer (bit 6)
// 2 32 bit values - high is for allowed 1-setting and lower for 0-setting
#define IA32_VMX_PINBASED_CTLS 0x481

// Capability Reporting Reg of Prim Proc-based VM-execution Controls (R/O)
// Bit 31 (value of 1) of the Prim processor-based VM-execution controls 
// indicates Sec processor-based VM-execution controls are used.
// Controls handling of synchronous events
// i.e., events caused by execution of specific instructions
// 2 32 bit values - high is for allowed 1-setting and lower for 0-setting
//
// Primary (partial description)
// 1-setting of ‘use time stamp counter offsetting’ (bit 3)
// RDTSC exiting control (bit 12)
// CR3 load exiting (bit 15), CR3 store (bit 16)
// Activate secondary controls (bit 31)
// 1-setting of ‘use I/O bitmaps’ (bit 25)
// 1-setting of ‘use MSR bitmaps’ (bit 28)
// Activate secondary controls (bit 31)
#define IA32_VMX_PROCBASED_CTLS 0x482

// Capability Reporting Reg of Sec Proc-based VM-execution Controls (R/O)
// Secondary (partial description)
// Enable EPT (bit 1)
// Enable VPID (bit 5)
// Enable VM functions (bit 13)
#define IA32_VMX_PROCBASED_CTLS2 0x48B

typedef struct  {
        unsigned int    eip;
        unsigned int    eflags;
        unsigned int    eax;
        unsigned int    ecx;
        unsigned int    edx;
        unsigned int    ebx;
        unsigned int    esp;
        unsigned int    ebp;
        unsigned int    esi;
        unsigned int    edi;
        unsigned int     es;
        unsigned int     cs;
        unsigned int     ss;
        unsigned int     ds;
        unsigned int     fs;
        unsigned int     gs;
} regs_ia32;

