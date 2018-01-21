#include "mykvm.h"

extern const unsigned char code32_paged[], code32_paged_end[];
void fill_segment_descriptor(uint64_t *dt, struct kvm_segment *seg)
{
	uint16_t index = seg->selector >> 3;
	uint32_t limit = seg->g ? seg->limit >> 12 : seg->limit;
	dt[index] = (limit & 0xffff) /* Limit bits 0:15 */
		| (seg->base & 0xffffff) << 16 /* Base bits 0:23 */
		| (uint64_t)seg->type << 40
		| (uint64_t)seg->s << 44 /* system or code/data */
		| (uint64_t)seg->dpl << 45 /* Privilege level */
		| (uint64_t)seg->present << 47
		| (limit & 0xf0000ULL) << 48 /* Limit bits 16:19 */
		| (uint64_t)seg->avl << 52 /* Available for system software */
		| (uint64_t)seg->l << 53 /* 64-bit code segment */
		| (uint64_t)seg->db << 54 /* 16/32-bit segment */
		| (uint64_t)seg->g << 55 /* 4KB granularity */
		| (seg->base & 0xff000000ULL) << 56; /* Base bits 24:31 */
}

setup_protected_mode(kvm *kvm, struct kvm_sregs *sregs) {
	struct kvm_segment seg = {
		.base = 0,
		.limit = 0xffffffff,
		.present = 1,
		.dpl = 0,
		.db = 1,
		.s = 1, /* Code/data */
		.l = 0,
		.g = 1, /* 4KB granularity */
	};
	uint64_t *gdt;

	printf("\n...setting up protected mode");
	sregs->cr0 |= CR0_PE; /* enter protected mode */
	sregs->gdt.base = 0x1000;
	sregs->gdt.limit = 3 * 8 - 1;

	gdt = (void *)(kvm->userspace_addr + sregs->gdt.base);
	/* gdt[0] is the null segment */

	seg.type = 11; /* Code: execute, read, accessed */
	seg.selector = 1 << 3;
	fill_segment_descriptor(gdt, &seg);
	sregs->cs = seg;

	seg.type = 3; /* Data: read/write, accessed */
	seg.selector = 2 << 3;
	fill_segment_descriptor(gdt, &seg);
	sregs->ds = sregs->es = sregs->fs = sregs->gs = sregs->ss = seg;

}
static void setup_paged_32bit_mode(kvm *kvm, struct kvm_sregs *sregs) {
	uint32_t pd_addr = 0x2000;
	uint32_t *pd = (void *)(kvm->userspace_addr + pd_addr);

	printf("\n...setting up paged 32 bit mode");
	/* A single 4MB page to cover the memory region */
	pd[0] = PDE32_PRESENT | PDE32_RW | PDE32_USER | PDE32_PS;
	/* Other PDEs are left zeroed, meaning not present. */

	sregs->cr3 = pd_addr;
	sregs->cr4 = CR4_PSE;
	sregs->cr0 = CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_WP | CR0_AM;
	sregs->efer = 0;
}

int run_paged_32bit_mode(kvm *kvm) {
	struct kvm_sregs sregs;
	struct kvm_regs regs;
	int status;

	status = ioctl(kvm->vcpufd, KVM_GET_SREGS, &sregs);
	setup_protected_mode(kvm, &sregs);
	setup_paged_32bit_mode(kvm, &sregs);
	status = ioctl(kvm->vcpufd, KVM_SET_SREGS, &sregs);

	memset(&regs, 0, sizeof(regs));
	regs.rip = 0x0;
	regs.rflags = 0x2;
	status = ioctl(kvm->vcpufd, KVM_SET_REGS, &regs);
	if (status == -1)
		printf("\n Protected Mode: setting SET_REGS failed");
}


/******
 * Running protected mode gives us the following perf events...
 *
 [root@localhost ~]# perf stat -e 'kvm:*' -a sleep 5
 Performance counter stats for 'system wide':
                 5      kvm:kvm_entry                                        
                 5      kvm:kvm_exit                                      
                 3      kvm:kvm_page_fault                                
                 1      kvm:kvm_cr                                        
                 1      kvm:kvm_write_tsc_offset                          
                 2      kvm:kvm_update_master_clock                         
                 1      kvm:kvm_track_tsc                                 
                 1      kvm:kvm_userspace_exit                            
                 2      kvm:kvm_fpu                                       
[root@localhost ~]#  
*/
