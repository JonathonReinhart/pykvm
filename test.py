#!/usr/bin/env python
import sys
import os, os.path
import mmap

import pykvm

def dump_extensions(kvm):
    for ext, sup in kvm.get_extensions():
        print '{:<40}: {}'.format(ext, sup)

def test_regs(vcpu):
    regs = vcpu.get_regs()
    print 'Registers:'
    print str(regs)

    regs.rax = 0xDEADBEEF2B84F00D
    vcpu.set_regs(regs)

    regs = vcpu.get_regs()
    print 'Registers (again):'
    print str(regs)

def test_sregs(vcpu):
    sregs = vcpu.get_sregs()
    print 'Special Registers:'
    print sregs

    sregs.cr0 |= ((1<<31) | (1<<30))
    vcpu.set_sregs(sregs)

    sregs = vcpu.get_sregs()
    print 'Special Registers (again):'
    print sregs


def map_file_to_guest(vm, filename, guest_phys_addr, size, readonly):
    # Unfortunately, ctypes doesn't support readonly memmaps, so we can't
    # really get the address of the memmap.

    with open(filename, 'rb') as f:
        data = f.read()

    assert(len(data) == size)

    m = mmap.mmap(-1, size)
    m[:] = data

    vm.add_mem_region(guest_phys_addr, m, readonly)


def main():
    kvm = pykvm.Kvm()

    #dump_extensions()

    vm = kvm.create_vm('MyVM')
    print vm

    vcpu = vm.add_vcpu(0)
    print vcpu

    #test_regs(vcpu)
    #test_sregs(vcpu)

    # Add some memory covering the top of 4GB (reset vector)
    sz = 64 << 10
    map_file_to_guest(vm, 'code.bin', 0xFFFFFFFF - sz + 1, sz, True)

    exit = vcpu.run()
    print exit
    print vcpu.get_regs()


    return 0

if __name__ == '__main__':
    sys.exit(main())

