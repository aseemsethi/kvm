#include "mykvm.h"

void kvm_enable_singlestep(kvm *kvm) {
	struct kvm_guest_debug debug = {
		.control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP,
	};
	if (ioctl(kvm->vcpufd, KVM_SET_GUEST_DEBUG, &debug) < 0)
		errx("KVM_SET_GUEST_DEBUG failed");
	printf("\n KVM Single Stepping Enabled");
}

static void print_dtable(const char *name, struct kvm_dtable *dtable)
{
	printf(" %s                 %016llx  %08hx\n",
		name, (uint64_t) dtable->base, (uint16_t) dtable->limit);
}

static void print_segment(const char *name, struct kvm_segment *seg)
{
	printf(" %s       %04hx      %016llx  %08x  %02hhx    %x %x   %x  %x %x %x %x\n",
	name, (uint16_t) seg->selector, (uint64_t) seg->base, (uint32_t) seg->limit,
	(uint8_t) seg->type, seg->present, seg->dpl, seg->db, seg->s, seg->l, seg->g, seg->avl);
}

void kvm_cpu__show_registers(kvm *kvm)
{
	unsigned long cr0, cr2, cr3;
	unsigned long cr4, cr8;
	unsigned long rax, rbx, rcx;
	unsigned long rdx, rsi, rdi;
	unsigned long rbp,  r8,  r9;
	unsigned long r10, r11, r12;
	unsigned long r13, r14, r15;
	unsigned long rip, rsp;
	struct kvm_sregs sregs;
	unsigned long rflags;
	struct kvm_regs regs;
	int i;

	if (ioctl(kvm->vcpufd, KVM_GET_REGS, &regs) < 0)
		errx("KVM_GET_REGS failed");

	memcpy(&kvm->regs, &regs, sizeof(regs));

	rflags = regs.rflags;

	rip = regs.rip; rsp = regs.rsp;
	rax = regs.rax; rbx = regs.rbx; rcx = regs.rcx;
	rdx = regs.rdx; rsi = regs.rsi; rdi = regs.rdi;
	rbp = regs.rbp; r8  = regs.r8;  r9  = regs.r9;
	r10 = regs.r10; r11 = regs.r11; r12 = regs.r12;
	r13 = regs.r13; r14 = regs.r14; r15 = regs.r15;

	printf("\n Registers:\n");
	printf(" ----------\n");
	printf(" rip: %016lx   rsp: %016lx flags: %016lx\n", rip, rsp, rflags);
	printf(" rax: %016lx   rbx: %016lx   rcx: %016lx\n", rax, rbx, rcx);
	printf(" rdx: %016lx   rsi: %016lx   rdi: %016lx\n", rdx, rsi, rdi);
	printf(" rbp: %016lx    r8: %016lx    r9: %016lx\n", rbp, r8,  r9);
	printf(" r10: %016lx   r11: %016lx   r12: %016lx\n", r10, r11, r12);
	printf(" r13: %016lx   r14: %016lx   r15: %016lx\n", r13, r14, r15);

	if (ioctl(kvm->vcpufd, KVM_GET_SREGS, &sregs) < 0)
		errx("KVM_GET_REGS failed");

	cr0 = sregs.cr0; cr2 = sregs.cr2; cr3 = sregs.cr3;
	cr4 = sregs.cr4; cr8 = sregs.cr8;

	printf(" cr0: %016lx   cr2: %016lx   cr3: %016lx\n", cr0, cr2, cr3);
	printf(" cr4: %016lx   cr8: %016lx\n", cr4, cr8);
	printf("\n Segment registers:\n");
	printf(  " ------------------\n");
	printf(" register  selector  base              limit     type  p dpl db s l g avl\n");
	print_segment("cs ", &sregs.cs);
	print_segment("ss ", &sregs.ss);
	print_segment("ds ", &sregs.ds);
	print_segment("es ", &sregs.es);
	print_segment("fs ", &sregs.fs);
	print_segment("gs ", &sregs.gs);
	print_segment("tr ", &sregs.tr);
	print_segment("ldt", &sregs.ldt);
	print_dtable("gdt", &sregs.gdt);
	print_dtable("idt", &sregs.idt);

	printf("\n Interrupt bitmap:\n");
	printf(  " -----------------\n");
	for (i = 0; i < (KVM_NR_INTERRUPTS + 63) / 64; i++)
		printf(" %016llx", (uint64_t) sregs.interrupt_bitmap[i]);
	printf("\n");
}
void kvm_dump_registers(kvm *kvm) {
	unsigned long rax, rbx, rcx;
	unsigned long rdx, rsi, rdi;
	unsigned long rbp,  r8,  r9;
	unsigned long r10, r11, r12;
	unsigned long r13, r14, r15;
	unsigned long rip, rsp;
	struct kvm_regs regs;

	if (ioctl(kvm->vcpufd, KVM_GET_REGS, &regs) < 0)
		errx("KVM_GET_REGS failed");
	else
		printf("\n Dumping Registers:");

	rip = regs.rip; rsp = regs.rsp;
	rax = regs.rax; rbx = regs.rbx; rcx = regs.rcx;
	rdx = regs.rdx; rsi = regs.rsi; rdi = regs.rdi;
	rbp = regs.rbp; r8  = regs.r8;  r9  = regs.r9;
	r10 = regs.r10; r11 = regs.r11; r12 = regs.r12;
	r13 = regs.r13; r14 = regs.r14; r15 = regs.r15;

	printf("Registers:\n");
	printf(" rip: %016lx   rsp: %016lx\n", rip, rsp);
	printf(" rax: %016lx   ebx: %016lx   ecx: %016lx\n", rax, rbx, rcx);
	printf(" rdx: %016lx   rsi: %016lx   rdi: %016lx\n", rdx, rsi, rdi);
	printf(" rbp: %016lx   r8:  %016lx   r9:  %016lx\n", rbp, r8,  r9);
	printf(" r10: %016lx   r11: %016lx   r12: %016lx\n", r10, r11, r12);
	printf(" r13: %016lx   r14: %016lx   r15: %016lx\n", r13, r14, r15);
}
