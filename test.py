#!/usr/bin/env python
import sys
import os, os.path
import mmap
import struct

import pykvm
from pykvm.exitreason import *

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
    return map_to_guest(vm, guest_phys_addr, data, readonly)

def map_to_guest(vm, guest_phys_addr, data, readonly):
    # TODO: What alignment?
    m = mmap.mmap(-1, len(data))
    m[:] = data
    vm.add_mem_region(guest_phys_addr, m, readonly)




def handle_io(vcpu, exit):
    if exit.is_write:
        pass
    else:
        exit.set_data(struct.pack('<I', 0xDEADBEEF))
    return True

def handle_int_err(vcpu, exit):
    print exit
    print vcpu.get_regs()
    print vcpu.get_sregs()

exit_map = {
    KvmExitIo: handle_io,
    KvmExitHlt: lambda v,x: False,
    KvmExitIntr: lambda v,x: False,
    KvmExitInternalError: handle_int_err,
}

def dispatch_exit(vcpu, exit):
    handler = exit_map.get(type(exit))
    if not handler:
        raise Exception('No handler for {}'.format(type(exit)))
    return handler(vcpu, exit)




def main():
    firmware_filename = sys.argv[1]
    kvm = pykvm.Kvm()

    #dump_extensions()

    vm = kvm.create_vm('MyVM')
    print vm

    vcpu = vm.add_vcpu(0)
    print vcpu

    #test_regs(vcpu)
    #test_sregs(vcpu)

    # 1 MB RAM
    m = mmap.mmap(-1, 1<<20)
    vm.add_mem_region(0, m)

    # Firmware
    with open(firmware_filename, 'rb') as f:
        fw = f.read()
    map_to_guest(vm, 0xFFFFFFFF - len(fw) + 1, fw, True)


    vcpu.enable_single_step()


    while True:
        exit = vcpu.run()
        print exit
        print vcpu.get_regs()

        if not dispatch_exit(vcpu, exit):
            break





    return 0

if __name__ == '__main__':
    sys.exit(main())

