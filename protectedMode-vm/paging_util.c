#include "mykvm.h"

extern const unsigned char code32_paged[], code32_paged_end[];
setup_protected_mode(kvm *kvm) {

}
static void setup_paged_32bit_mode(kvm *kvm) {

}
int run_paged_32bit_mode(kvm *kvm) {
	struct kvm_sregs sregs;
	struct kvm_regs regs;
	int status;

	status = ioctl(kvm->vcpufd, KVM_GET_SREGS, &sregs);
	setup_protected_mode(kvm);
	setup_paged_32bit_mode(kvm);
	status = ioctl(kvm->vcpufd, KVM_SET_SREGS, &sregs);

	memset(&regs, 0, sizeof(regs));
	regs.rip = 0x0;
	regs.rflags = 0x2;
	status = ioctl(kvm->vcpufd, KVM_SET_REGS, &regs);
}
