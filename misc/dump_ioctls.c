#include <stdio.h>
#include <linux/kvm.h>

#define pr(x)   printf("%-30s = 0x%08X\n", #x, x)

int main(void)
{
    pr(KVM_GET_API_VERSION);
    pr(KVM_CREATE_VM);
    pr(KVM_GET_MSR_INDEX_LIST);
    pr(KVM_CHECK_EXTENSION);
    pr(KVM_GET_VCPU_MMAP_SIZE);

    return 0;
}