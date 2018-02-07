/*
 * MSRs: If bit 55 in the IA32_VMX_BASIC MSR is read as 0, all information 
 * about the allowed settings of the pin-based VM-execution controls is 
 * contained in the IA32_VMX_PINBASED_CTLS MSR. The pin controls are deined in 
 * Section 24.6.1. e.g. 
 * Bit0 - External Int exit - if "1", external int cause VM exits
 * Bit3 - NMI exit - if "1", NMI cause VM exit
 * Bits 31:0 indicate the allowed 0-settings of these controls. VM entry allows 
 * control X (bit X of the pin-based VM-execution controls) to be 0 if bit X 
 * in the MSR is cleared to 0.
 * Bits 63:32 indicate the allowed 1-settings of these controls. VM entry allows
 * control X to be 1 if bit 32+X in the MSR is set to 1; if bit 32+X in the MSR
 * is cleared to 0, VM entry fails if control X is 1.
 * Ref: A3.1 Intel Arch
 */
#include "wiser.h"
#include <linux/mm.h>
#include <linux/proc_fs.h>	// for create proc entry
#include <linux/seq_file.h>
#include <linux/fs.h>		// struct file ops
#include <linux/mm.h>		// for remap_pfn_range
#include <linux/mutex.h>	// for mutexs
#include <asm/io.h>		// for virt_to_phys()
#include <asm/uaccess.h>		// for copy_from_user()
#include <linux/miscdevice.h>		// for copy_from_user()
//#include "machine.h"		// for VMCS fields
#include <linux/slab.h>		// for kmalloc()
#include <linux/delay.h>


#define N_ARENAS 11 		// number of 64 KB mem allocations
#define ARENA_LENGTH (64<<10)	// 65536 - size of each allocated mem area
#define MSR_VMX_CAPS 0x480	// index of VMX Capabilities MSRs
#define LEGACY_REACH 0x110000	// end of real addressible mem - 1114112
// This 64KB above the 1 MB boundary

#define PAGE_DIR_OFFSET	0x2000
#define PAGE_TBL_OFFSET	0x3000

#define IDT_KERN_OFFSET	0x4000 // 16384
#define GDT_KERN_OFFSET	0x4800 // 18432 - (2k diff)
#define LDT_KERN_OFFSET	0x4A00 // 18944 - (512 bytes diff

#define TSS_KERN_OFFSET	0x4C00 // 19546 - (512 bytes diff)
#define TOS_KERN_OFFSET	0x8000 // 32768
#define MSR_KERN_OFFSET	0x8000

#define __SELECTOR_TASK	0x0008
#define __SELECTOR_LDTR	0x0004
#define __SELECTOR_CODE	0x0004
#define __SELECTOR_DATA	0x000C
#define __SELECTOR_VRAM	0x0014
#define __SELECTOR_FLAT	0x001C

char modname[] = "wiser";
int my_major=108;
char cpu_oem[16];
int cpu_features;
void *kmem[N_ARENAS];

unsigned long msr0x480[11];
unsigned long msr_efer;
unsigned long vmxon_region;
unsigned long guest_region;
unsigned long pgdir_region;
unsigned long pgtbl_region;
unsigned long g_IDT_region;
unsigned long g_GDT_region;
unsigned long g_LDT_region;
unsigned long g_TSS_region;
unsigned long g_TOS_region;
unsigned long h_MSR_region;

unsigned long cr0, cr4;
u32 regsitered=-1;

DEFINE_MUTEX(my_mutex);

typedef struct vm_t {
	uint32_t vmcs_num_bytes;
	int	vmxSupport;
	int	eptSupport;
	unsigned long cr0, cr4;
	unsigned long msr_efer;
} vmStruct;
vmStruct vm;

unsigned short _gdtr[5], _idtr[5];
unsigned int _eax, _ebx, _ecx, _edx, _esp, _ebp, _esi, _edi;
long wiser_dev_ioctl( struct file *file, unsigned int count, 
					  unsigned long buf) {

/*
	unsigned long *gdt, *ldt, *idt;
	unsigned int *pgtbl, *pgdir, *tss, phys_addr = 0;
	int i,j;
*/
	int ret;
	
	printk("wiser_dev_ioctl...\n");
	ret = mutex_trylock(&my_mutex);
	if (ret == 0) {
		return -ERESTARTSYS;
	}
	// client needs to pass data equal to register-state amount
	if(count != sizeof(regs_ia32)) {
		mutex_unlock(&my_mutex);
		return -EINVAL;
	}
	// reinitialize the VM Control Structures
	memset(phys_to_virt(vmxon_region), 0x00, PAGE_SIZE);
	memset(phys_to_virt(guest_region), 0x00, PAGE_SIZE);
	memcpy(phys_to_virt(vmxon_region), msr0x480, 4);
	memcpy(phys_to_virt(guest_region), msr0x480, 4);
	

	return 1;
}
int wiser_dev_mmap(struct file *file, struct vm_area_struct *vma ){
	return 1;
}

struct file_operations wiser_dev_ops = {
	.unlocked_ioctl = wiser_dev_ioctl,
	.compat_ioctl = wiser_dev_ioctl,
	.mmap = wiser_dev_mmap,
};
struct miscdevice wiser_dev = {
	MISC_DYNAMIC_MINOR,
	"wiser",
	&wiser_dev_ops,
};

int checkProcessor() {
	u32 low, hi;

	getProcCpuid();
	getCrRegs();
	getMSR(IA32_VMX_BASIC,  &low, &hi);
	vm.vmcs_num_bytes  =  hi & 0xfff; // Bits 44:32
	printk("vmcs_num_bytes = 0x%x\n", vm.vmcs_num_bytes);

	//verify processor supports Intel Virt Tech
	asm("xor %%eax, %%eax		\n"\
	    "cpuid			\n"\
	    "mov %%ebx, cpu_oem+0	\n"\
	    "mov %%edx, cpu_oem+4	\n"\
	    "mov %%ecx, cpu_oem+8	\n"\
	    :::"ax", "bx","cx","dx");
	printk("Prosessor is %s\n", cpu_oem);
	// check if proc has VMX support
	vm.vmxSupport = vmxCheckSupport(1);
	if (vm.vmxSupport ==1)
		printk("VMX supported by chipset\n");
	else {
		printk("VMX not supported by chipset\n");
		return -1;
	}
	
	// check if proc has EPT support
	vm.eptSupport = vmxCheckSupportEPT();
	if (vm.eptSupport ==1)
		printk("EPT supported by chipset\n");
	else
		printk("EPT not supported by chipset\n");

	// read all MSRs into the msr0x480 array
	asm(    " xor   %%rbx, %%rbx                    \n"\
                " mov   %0, %%rcx                       \n"\
                "nxcap:                                 \n"\
                " rdmsr                                 \n"\
                " mov   %%eax, msr0x480+0(, %%rbx, 8)   \n"\
                " mov   %%edx, msr0x480+4(, %%rbx, 8)   \n"\
                " inc   %%rcx                           \n"\
                " inc   %%rbx                           \n"\
                " cmp   $11, %%rbx                      \n"\
                " jb    nxcap                           \n"\
           :: "i" (MSR_VMX_CAPS) : "ax", "bx", "cx", "dx"  );

	// Save 32bit cr0, cr4 in our VM struct
	asm( " mov %%cr0, %%rax \n mov %%rax, cr0 " ::: "ax" );
	asm( " mov %%cr4, %%rax \n mov %%rax, cr4 " ::: "ax" );
	vm.cr0 = cr0;
	vm.cr4 = cr4;	
	printk("cr0 = 0x%016lx\n", vm.cr0);
	printk("cr4 = 0x%016lx\n", vm.cr4);

	// Get EFER MSR
	asm( "mov %0, %%ecx		\n"\
		 "rdmsr				\n"\
		 "mov %%eax, msr_efer+0 \n"\
		 "mov %%edx, msr_efer+4 \n"\
		::"i" (MSR_EFER): "ax", "cx", "dx");
	printk("EFER MSR = 0x%016lX\n", msr_efer);
	vm.msr_efer = msr_efer;

	return 0;
}

void assignAddresses() {
	vmxon_region = virt_to_phys(kmem[10] + 0x000);
	guest_region = virt_to_phys(kmem[10] + 0x1000);

	pgdir_region = virt_to_phys(kmem[10] + PAGE_DIR_OFFSET);
	pgtbl_region = virt_to_phys(kmem[10] + PAGE_TBL_OFFSET);

	g_IDT_region = virt_to_phys(kmem[10] + IDT_KERN_OFFSET);
	g_GDT_region = virt_to_phys(kmem[10] + GDT_KERN_OFFSET);
	g_LDT_region = virt_to_phys(kmem[10] + LDT_KERN_OFFSET);

	g_TSS_region = virt_to_phys(kmem[10] + TSS_KERN_OFFSET);
	g_TOS_region = virt_to_phys(kmem[10] + TOS_KERN_OFFSET);
	h_MSR_region = virt_to_phys(kmem[10] + MSR_KERN_OFFSET);
}


struct proc_dir_entry *proc_file_entry = NULL;

static int wiser_show(struct seq_file *m, void *v) {
	int i;

	seq_printf(m, "Hello proc!\n");
	seq_printf(m, "\n\t%s\n\n", "VMX Capability MSRs");
    for (i = 0; i < 11; i++) {
        seq_printf(m, "\tMSR0x%X=", 0x480 + i);
        seq_printf(m, "%016lX \n", msr0x480[i]);
	}
    seq_printf(m, "CR0=%016lX  ", vm.cr0 );
    seq_printf(m, "CR4=%016lX  ", vm.cr4 );
    seq_printf(m, "EFER=%016lX \n ", vm.msr_efer );

    seq_printf(m, "vmxon_region=%016lX \n", vmxon_region );
    seq_printf(m, "\n" );
    seq_printf(m, "guest_region=%016lX \n", guest_region );
    seq_printf(m, "pgdir_region=%016lX \n", pgdir_region );
    seq_printf(m, "pgtbl_region=%016lX \n", pgtbl_region );
    seq_printf(m, "g_IDT_region=%016lX \n", g_IDT_region );
    seq_printf(m, "g_GDT_region=%016lX \n", g_GDT_region );
    seq_printf(m, "g_LDT_region=%016lX \n", g_LDT_region );
    seq_printf(m, "g_TSS_region=%016lX \n", g_TSS_region );
    seq_printf(m, "g_TOS_region=%016lX \n", g_TOS_region );
    seq_printf(m, "h_MSR_region=%016lX \n", h_MSR_region );

	return 0;
}

static int wiser_open(struct inode *inode, struct  file *file) {
  return single_open(file, wiser_show, NULL);
}

static const struct file_operations wiserInfo = {
  .owner = THIS_MODULE,
  .open = wiser_open,
  .read = seq_read,
  .llseek = seq_lseek,
  .release = single_release,
};

int wiser_main() {
	u32 i, j, status;

	status = checkProcessor();
	if (status == -1) {
		printk("\n VMX not supported on processor !!!");
		return -1;
	}

	// Create /dev/wiser
	// crw------- 1 root root 10, 57 Feb  4 10:51 /dev/wiser
	wiser_dev_ops.owner = THIS_MODULE;
	regsitered = misc_register(&wiser_dev);
	if(regsitered) {
		printk(KERN_ERR "Wiser: misc dev register failed\n");
		return -1;
	}
	// Check if /dev/[modname] has been created
	printk("Ensure that /dev/wiser has been created\n");

	// allocate page-aligned blocks of non-pageable kernel mem
	for (i=0;i<N_ARENAS; i++) {
		kmem[i] = kmalloc(ARENA_LENGTH, GFP_KERNEL);
		if (kmem[i] == NULL) {
			for(j=0;j<i;j++) kfree(kmem[j]);
			return -ENOMEM;
		} else 
			memset(kmem[i], 0x00, ARENA_LENGTH);
	}

	// Assign usages to mem areas
	assignAddresses();

	// enable VM extensions (bit 13 in CR4)
	setCr4Vmxe(NULL);
	smp_call_function(setCr4Vmxe, NULL, 1);
	proc_file_entry = proc_create(modname, 0, NULL, &wiserInfo);
	if(proc_file_entry == NULL) {
		printk("Could not create proc entry\n");
		return 0;
	}

	msleep(10000);
	return 0;
}

int wiser_exit() {
	// deregister only if previosuly registered
	if (regsitered == 0)
		misc_deregister(&wiser_dev);
	if(proc_file_entry != NULL)
		remove_proc_entry(modname, NULL);
	// for(j=0;j<i;j++) kfree(kmem[j]);
	return 0;
}
