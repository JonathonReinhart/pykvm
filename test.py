#!/usr/bin/env python
import sys
import os, os.path

import pykvm

def main():
    kvm = pykvm.Kvm()

    print 'VCPU_MMAP_SIZE: 0x{:X}'.format(kvm._get_vcpu_mmap_size())

    for ext, sup in kvm.get_extensions():
        print '{:<40}: {}'.format(ext, sup)

    vm = kvm.create_vm('MyVM')
    print vm

    vcpu = vm.add_vcpu(0)
    print vcpu

    regs = vcpu.get_regs()
    print 'Registers:'
    print str(regs)

    regs.rax = 0xDEADBEEF2B84F00D
    vcpu.set_regs(regs)

    regs = vcpu.get_regs()
    print 'Registers (again):'
    print str(regs)

    sregs = vcpu.get_sregs()
    print 'Special Registers:'
    print sregs

    sregs.cr0 |= ((1<<31) | (1<<30))
    vcpu.set_sregs(sregs)

    sregs = vcpu.get_sregs()
    print 'Special Registers (again):'
    print sregs

    vcpu.run()

    return 0

if __name__ == '__main__':
    sys.exit(main())

