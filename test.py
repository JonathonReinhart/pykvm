#!/usr/bin/env python
import sys
import os, os.path

import pykvm

def main():
    kvm = pykvm.Kvm()

    for ext, sup in kvm.get_extensions():
        print '{:<40}: {}'.format(ext, sup)

    vm = kvm.create_vm('MyVM')
    print vm

    vcpu = vm.add_vcpu(0)
    print vcpu

    regs = vcpu.get_regs()
    print str(regs)

    regs.rax = 0xDEADBEEF2B84F00D
    vcpu.set_regs(regs)

    regs = vcpu.get_regs()
    print str(regs)

    sregs = vcpu.get_sregs()
    print sregs


    return 0

if __name__ == '__main__':
    sys.exit(main())

