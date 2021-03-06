#include <stdio.h>
#include <linux/kvm.h>

#define pr(x)   printf("  %-30s = 0x%08lX\n", #x, (long unsigned int)x)

int main(void)
{
    printf("System IOCTLs:\n");
    pr(KVM_GET_API_VERSION);
    pr(KVM_CREATE_VM);
    pr(KVM_GET_MSR_INDEX_LIST);
    pr(KVM_CHECK_EXTENSION);
    pr(KVM_GET_VCPU_MMAP_SIZE);

    printf("VM IOCTLs:\n");
    pr(KVM_CREATE_VCPU);
    pr(KVM_SET_USER_MEMORY_REGION);

    printf("VCPU IOCTLs:\n");
    pr(KVM_RUN);
    pr(KVM_GET_REGS);
    pr(KVM_SET_REGS);
    pr(KVM_GET_SREGS);
    pr(KVM_SET_SREGS);
    pr(KVM_GET_DEBUGREGS);
    pr(KVM_SET_DEBUGREGS);
    pr(KVM_TRANSLATE);
    pr(KVM_INTERRUPT);
    pr(KVM_GET_MSRS);
    pr(KVM_SET_MSRS);
    pr(KVM_SET_CPUID);
    pr(KVM_SET_GUEST_DEBUG);

    return 0;
}
