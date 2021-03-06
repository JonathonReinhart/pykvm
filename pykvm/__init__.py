# pykvm
# https://github.com/JonathonReinhart/pykvm
# (C) 2015 Jonathon Reinhart

import os
import struct
from fcntl import fcntl, ioctl
import mmap
import ctypes
import time 

from kvmstructs import *
from exitreason import *

__all__ = ['Kvm', 'KvmError']

class KvmError(Exception):
    pass


class Vcpu(object):
    def __init__(self, vm, fd, cpuid):
        self.vm = vm
        self.fd = fd
        self.cpuid = cpuid

        self._map_vcpu_area()


    def __str__(self):
        return '<Vcpu: vm={} fd={} cpuid={}>'.format(
                self.vm.name, self.fd, self.cpuid)

    def _map_vcpu_area(self):
        # http://stackoverflow.com/a/3640617
        sz = self.vm.kvm._get_vcpu_mmap_size()
        self.mmap = mmap.mmap(self.fd, sz, mmap.MAP_SHARED, (mmap.PROT_READ|mmap.PROT_WRITE))
        self.kvm_run = kvm_run.from_buffer(self.mmap)

    def run(self):
        t0 = time.time()
        try:
            self._run()
        except KeyboardInterrupt:
            pass
        dt = time.time() - t0
        return KvmExit.from_vcpu(self, dt)

    def enable_single_step(self):
        dbg = kvm_guest_debug()
        dbg.control = self.KVM_GUESTDBG_ENABLE | self.KVM_GUESTDBG_SINGLESTEP 
        self._set_guest_debug(dbg)


    # IOCTLs
    KVM_RUN                        = 0x0000AE80
    KVM_GET_REGS                   = 0x8090AE81
    KVM_SET_REGS                   = 0x4090AE82
    KVM_GET_SREGS                  = 0x8138AE83
    KVM_SET_SREGS                  = 0x4138AE84
    KVM_GET_DEBUGREGS              = 0x8080AEA1
    KVM_SET_DEBUGREGS              = 0x4080AEA2
    KVM_TRANSLATE                  = 0xC018AE85
    KVM_INTERRUPT                  = 0x4004AE86
    KVM_GET_MSRS                   = 0xC008AE88
    KVM_SET_MSRS                   = 0x4008AE89
    KVM_SET_CPUID                  = 0x4008AE8A
    KVM_SET_GUEST_DEBUG            = 0x4048AE9B

    # SET_GUEST_DEBUG
    KVM_GUESTDBG_ENABLE            = 0x00000001
    KVM_GUESTDBG_SINGLESTEP        = 0x00000002


    def _run(self):
        ioctl(self.fd, self.KVM_RUN)

    def get_regs(self):
        r = kvm_regs()
        ioctl(self.fd, self.KVM_GET_REGS, r)
        return r

    def set_regs(self, regs):
        ioctl(self.fd, self.KVM_SET_REGS, regs)

    def get_sregs(self):
        r = kvm_sregs()
        ioctl(self.fd, self.KVM_GET_SREGS, r)
        return r

    def set_sregs(self, regs):
        ioctl(self.fd, self.KVM_SET_SREGS, regs)

    def get_debugregs(self):
        r = kvm_debugregs()
        ioctl(self.fd, self.KVM_GET_DEBUGREGS, r)
        return r

    def set_debugregs(self, regs):
        ioctl(self.fd, self.KVM_SET_DEBUGREGS, regs)

    def _set_guest_debug(self, dbg):
        ioctl(self.fd, self.KVM_SET_GUEST_DEBUG, dbg)



class Memslot(object):
    def __init__(self, slotnum, guest_phys_addr, buffer_obj, readonly=False):
        self.slotnum = slotnum
        self.guest_phys_addr = guest_phys_addr
        self.buffer_obj = buffer_obj
        self.readonly = readonly

    def __str__(self):
        return '<Memslot #{}: 0x{:X}-0x{:X}{}>'.format(self.slotnum,
                self.guest_phys_addr, self.guest_phys_addr + self.size,
                ' Readonly ' if self.readonly else '',)

    @property
    def size(self):
        return len(self.buffer_obj)

    @property
    def userspace_addr(self):
        return addressof_buffer(self.buffer_obj)


def addressof_buffer(b):
    # This seems like a hack, but I could find no better way.
    return ctypes.addressof(ctypes.c_void_p.from_buffer(b))


class Vm(object):
    def __init__(self, kvm, fd, name):
        self.kvm = kvm
        self.fd = fd
        self.name = name

        self.vcpus = {}

        self.memslots = []


    def __str__(self):
        return '<Vm: fd={} name={}>'.format(self.fd, self.name)

    def add_vcpu(self, cpuid):
        if cpuid in self.vcpus:
            raise KvmError('vcpu with id {} already exists'.format(cpuid))
        fd = self._create_vcpu(cpuid)
        vcpu = Vcpu(self, fd, cpuid)
        self.vcpus[cpuid] = vcpu
        return vcpu

    def add_mem_region(self, guest_phys_addr, buffer_obj, readonly=False):
        if len(self.memslots) >= self.kvm.max_memslots:
            raise KvmError('Maximum number of memory slots ({}) already assigned.'\
                    .format(self.kvm.max_memslots))
        slotnum = len(self.memslots)
        ms = Memslot(slotnum, guest_phys_addr, buffer_obj, readonly)
        self.update_mem_region(ms)
        self.memslots.append(ms)


    def update_mem_region(self, ms):
        flags = 0
        if ms.readonly:
            flags |= kvm_userspace_memory_region.KVM_MEM_READONLY 
        self._set_user_memory_region(ms.slotnum, flags, ms.guest_phys_addr, ms.size, ms.userspace_addr)


    # IOCTLs
    KVM_CREATE_VCPU                = 0x0000AE41
    KVM_SET_USER_MEMORY_REGION     = 0x4020AE46

    def _create_vcpu(self, cpuid):
        return ioctl(self.fd, self.KVM_CREATE_VCPU, cpuid)

    def _set_user_memory_region(self, slot, flags, guest_phys_addr, memory_size, userspace_addr):
        r = kvm_userspace_memory_region(
                slot = slot, flags = flags, guest_phys_addr = guest_phys_addr,
                memory_size = memory_size, userspace_addr = userspace_addr)
        ioctl(self.fd, self.KVM_SET_USER_MEMORY_REGION, r)






class Kvm(object):
    KVM_API_VERSION = 12

    def __init__(self):
        self.fd = os.open('/dev/kvm', os.O_RDWR)
        self.vms = []

        self._check_api_version()
        self.max_memslots = self._check_extension(self.KVM_CAP_NR_MEMSLOTS)

    def _check_api_version(self):
        ver = self._get_api_version() 
        if ver != Kvm.KVM_API_VERSION:
            raise KvmError('KVM API version unsupported: {}'.format(ver))

    def get_extensions(self):
        for name, cap in sorted(self._caps.iteritems()):
            yield (name, self._check_extension(cap))

    def create_vm(self, name=''):
        fd = self._create_vm()
        vm = Vm(self, fd, name)
        self.vms.append(vm)
        return vm


    # IOCTLs
    KVM_GET_API_VERSION            = 0x0000AE00
    KVM_CREATE_VM                  = 0x0000AE01
    KVM_GET_MSR_INDEX_LIST         = 0xC004AE02
    KVM_CHECK_EXTENSION            = 0x0000AE03
    KVM_GET_VCPU_MMAP_SIZE         = 0x0000AE04

    def _get_api_version(self):
        return ioctl(self.fd, Kvm.KVM_GET_API_VERSION) 

    def _get_vcpu_mmap_size(self):
        return ioctl(self.fd, Kvm.KVM_GET_VCPU_MMAP_SIZE)

    def _check_extension(self, cap):
        return ioctl(self.fd, Kvm.KVM_CHECK_EXTENSION, cap)

    def _create_vm(self):
        return ioctl(self.fd, Kvm.KVM_CREATE_VM, 0)


    KVM_CAP_IRQCHIP = 0
    KVM_CAP_HLT = 1
    KVM_CAP_MMU_SHADOW_CACHE_CONTROL = 2
    KVM_CAP_USER_MEMORY = 3
    KVM_CAP_SET_TSS_ADDR = 4
    KVM_CAP_VAPIC = 6
    KVM_CAP_EXT_CPUID = 7
    KVM_CAP_CLOCKSOURCE = 8
    KVM_CAP_NR_VCPUS = 9
    KVM_CAP_NR_MEMSLOTS = 10
    KVM_CAP_PIT = 11
    KVM_CAP_NOP_IO_DELAY = 12
    KVM_CAP_PV_MMU = 13
    KVM_CAP_MP_STATE = 14
    KVM_CAP_COALESCED_MMIO = 15
    KVM_CAP_SYNC_MMU = 16
    KVM_CAP_DEVICE_ASSIGNMENT = 17
    KVM_CAP_IOMMU = 18
    KVM_CAP_DEVICE_MSI = 20
    KVM_CAP_DESTROY_MEMORY_REGION_WORKS = 21
    KVM_CAP_USER_NMI = 22
    KVM_CAP_SET_GUEST_DEBUG = 23
    KVM_CAP_REINJECT_CONTROL = 24
    KVM_CAP_IRQ_ROUTING = 25
    KVM_CAP_IRQ_INJECT_STATUS = 26
    KVM_CAP_DEVICE_DEASSIGNMENT = 27
    KVM_CAP_DEVICE_MSIX = 28
    KVM_CAP_ASSIGN_DEV_IRQ = 29
    KVM_CAP_JOIN_MEMORY_REGIONS_WORKS = 30
    KVM_CAP_MCE = 31
    KVM_CAP_IRQFD = 32
    KVM_CAP_PIT2 = 33
    KVM_CAP_SET_BOOT_CPU_ID = 34
    KVM_CAP_PIT_STATE2 = 35
    KVM_CAP_IOEVENTFD = 36
    KVM_CAP_SET_IDENTITY_MAP_ADDR = 37
    KVM_CAP_XEN_HVM = 38
    KVM_CAP_INTERNAL_ERROR_DATA = 40
    KVM_CAP_VCPU_EVENTS = 41
    KVM_CAP_S390_PSW = 42
    KVM_CAP_PPC_SEGSTATE = 43
    KVM_CAP_HYPERV = 44
    KVM_CAP_HYPERV_VAPIC = 45
    KVM_CAP_HYPERV_SPIN = 46
    KVM_CAP_PCI_SEGMENT = 47
    KVM_CAP_PPC_PAIRED_SINGLES = 48
    KVM_CAP_INTR_SHADOW = 49
    KVM_CAP_DEBUGREGS = 50
    KVM_CAP_X86_ROBUST_SINGLESTEP = 51
    KVM_CAP_PPC_OSI = 52
    KVM_CAP_PPC_UNSET_IRQ = 53
    KVM_CAP_ENABLE_CAP = 54
    KVM_CAP_XSAVE = 55
    KVM_CAP_XCRS = 56
    KVM_CAP_PPC_GET_PVINFO = 57
    KVM_CAP_PPC_IRQ_LEVEL = 58
    KVM_CAP_ASYNC_PF = 59
    KVM_CAP_TSC_CONTROL = 60
    KVM_CAP_GET_TSC_KHZ = 61
    KVM_CAP_PPC_BOOKE_SREGS = 62
    KVM_CAP_SPAPR_TCE = 63
    KVM_CAP_PPC_SMT = 64
    KVM_CAP_PPC_RMA = 65
    KVM_CAP_MAX_VCPUS = 66
    KVM_CAP_PPC_HIOR = 67
    KVM_CAP_PPC_PAPR = 68
    KVM_CAP_SW_TLB = 69
    KVM_CAP_ONE_REG = 70
    KVM_CAP_S390_GMAP = 71
    KVM_CAP_TSC_DEADLINE_TIMER = 72
    KVM_CAP_S390_UCONTROL = 73
    KVM_CAP_SYNC_REGS = 74
    KVM_CAP_PCI_2_3 = 75
    KVM_CAP_KVMCLOCK_CTRL = 76
    KVM_CAP_SIGNAL_MSI = 77
    KVM_CAP_PPC_GET_SMMU_INFO = 78
    KVM_CAP_S390_COW = 79
    KVM_CAP_PPC_ALLOC_HTAB = 80
    KVM_CAP_READONLY_MEM = 81
    KVM_CAP_IRQFD_RESAMPLE = 82
    KVM_CAP_PPC_BOOKE_WATCHDOG = 83
    KVM_CAP_PPC_HTAB_FD = 84
    KVM_CAP_S390_CSS_SUPPORT = 85
    KVM_CAP_PPC_EPR = 86
    KVM_CAP_ARM_PSCI = 87
    KVM_CAP_ARM_SET_DEVICE_ADDR = 88
    KVM_CAP_DEVICE_CTRL = 89
    KVM_CAP_IRQ_MPIC = 90
    KVM_CAP_PPC_RTAS = 91
    KVM_CAP_IRQ_XICS = 92
    KVM_CAP_HYPERV_TIME = 96
    KVM_CAP_IOAPIC_POLARITY_IGNORED = 97

    _caps = {
        'KVM_CAP_IRQCHIP' : KVM_CAP_IRQCHIP,
        'KVM_CAP_HLT' : KVM_CAP_HLT,
        'KVM_CAP_MMU_SHADOW_CACHE_CONTROL' : KVM_CAP_MMU_SHADOW_CACHE_CONTROL,
        'KVM_CAP_USER_MEMORY' : KVM_CAP_USER_MEMORY,
        'KVM_CAP_SET_TSS_ADDR' : KVM_CAP_SET_TSS_ADDR,
        'KVM_CAP_VAPIC' : KVM_CAP_VAPIC,
        'KVM_CAP_EXT_CPUID' : KVM_CAP_EXT_CPUID,
        'KVM_CAP_CLOCKSOURCE' : KVM_CAP_CLOCKSOURCE,
        'KVM_CAP_NR_VCPUS' : KVM_CAP_NR_VCPUS,
        'KVM_CAP_NR_MEMSLOTS' : KVM_CAP_NR_MEMSLOTS,
        'KVM_CAP_PIT' : KVM_CAP_PIT,
        'KVM_CAP_NOP_IO_DELAY' : KVM_CAP_NOP_IO_DELAY,
        'KVM_CAP_PV_MMU' : KVM_CAP_PV_MMU,
        'KVM_CAP_MP_STATE' : KVM_CAP_MP_STATE,
        'KVM_CAP_COALESCED_MMIO' : KVM_CAP_COALESCED_MMIO,
        'KVM_CAP_SYNC_MMU' : KVM_CAP_SYNC_MMU,
        'KVM_CAP_DEVICE_ASSIGNMENT' : KVM_CAP_DEVICE_ASSIGNMENT,
        'KVM_CAP_IOMMU' : KVM_CAP_IOMMU,
        'KVM_CAP_DEVICE_MSI' : KVM_CAP_DEVICE_MSI,
        'KVM_CAP_DESTROY_MEMORY_REGION_WORKS' : KVM_CAP_DESTROY_MEMORY_REGION_WORKS,
        'KVM_CAP_USER_NMI' : KVM_CAP_USER_NMI,
        'KVM_CAP_SET_GUEST_DEBUG' : KVM_CAP_SET_GUEST_DEBUG,
        'KVM_CAP_REINJECT_CONTROL' : KVM_CAP_REINJECT_CONTROL,
        'KVM_CAP_IRQ_ROUTING' : KVM_CAP_IRQ_ROUTING,
        'KVM_CAP_IRQ_INJECT_STATUS' : KVM_CAP_IRQ_INJECT_STATUS,
        'KVM_CAP_DEVICE_DEASSIGNMENT' : KVM_CAP_DEVICE_DEASSIGNMENT,
        'KVM_CAP_DEVICE_MSIX' : KVM_CAP_DEVICE_MSIX,
        'KVM_CAP_ASSIGN_DEV_IRQ' : KVM_CAP_ASSIGN_DEV_IRQ,
        'KVM_CAP_JOIN_MEMORY_REGIONS_WORKS' : KVM_CAP_JOIN_MEMORY_REGIONS_WORKS,
        'KVM_CAP_MCE' : KVM_CAP_MCE,
        'KVM_CAP_IRQFD' : KVM_CAP_IRQFD,
        'KVM_CAP_PIT2' : KVM_CAP_PIT2,
        'KVM_CAP_SET_BOOT_CPU_ID' : KVM_CAP_SET_BOOT_CPU_ID,
        'KVM_CAP_PIT_STATE2' : KVM_CAP_PIT_STATE2,
        'KVM_CAP_IOEVENTFD' : KVM_CAP_IOEVENTFD,
        'KVM_CAP_SET_IDENTITY_MAP_ADDR' : KVM_CAP_SET_IDENTITY_MAP_ADDR,
        'KVM_CAP_XEN_HVM' : KVM_CAP_XEN_HVM,
        'KVM_CAP_INTERNAL_ERROR_DATA' : KVM_CAP_INTERNAL_ERROR_DATA,
        'KVM_CAP_VCPU_EVENTS' : KVM_CAP_VCPU_EVENTS,
        'KVM_CAP_S390_PSW' : KVM_CAP_S390_PSW,
        'KVM_CAP_PPC_SEGSTATE' : KVM_CAP_PPC_SEGSTATE,
        'KVM_CAP_HYPERV' : KVM_CAP_HYPERV,
        'KVM_CAP_HYPERV_VAPIC' : KVM_CAP_HYPERV_VAPIC,
        'KVM_CAP_HYPERV_SPIN' : KVM_CAP_HYPERV_SPIN,
        'KVM_CAP_PCI_SEGMENT' : KVM_CAP_PCI_SEGMENT,
        'KVM_CAP_PPC_PAIRED_SINGLES' : KVM_CAP_PPC_PAIRED_SINGLES,
        'KVM_CAP_INTR_SHADOW' : KVM_CAP_INTR_SHADOW,
        'KVM_CAP_DEBUGREGS' : KVM_CAP_DEBUGREGS,
        'KVM_CAP_X86_ROBUST_SINGLESTEP' : KVM_CAP_X86_ROBUST_SINGLESTEP,
        'KVM_CAP_PPC_OSI' : KVM_CAP_PPC_OSI,
        'KVM_CAP_PPC_UNSET_IRQ' : KVM_CAP_PPC_UNSET_IRQ,
        'KVM_CAP_ENABLE_CAP' : KVM_CAP_ENABLE_CAP,
        'KVM_CAP_XSAVE' : KVM_CAP_XSAVE,
        'KVM_CAP_XCRS' : KVM_CAP_XCRS,
        'KVM_CAP_PPC_GET_PVINFO' : KVM_CAP_PPC_GET_PVINFO,
        'KVM_CAP_PPC_IRQ_LEVEL' : KVM_CAP_PPC_IRQ_LEVEL,
        'KVM_CAP_ASYNC_PF' : KVM_CAP_ASYNC_PF,
        'KVM_CAP_TSC_CONTROL' : KVM_CAP_TSC_CONTROL,
        'KVM_CAP_GET_TSC_KHZ' : KVM_CAP_GET_TSC_KHZ,
        'KVM_CAP_PPC_BOOKE_SREGS' : KVM_CAP_PPC_BOOKE_SREGS,
        'KVM_CAP_SPAPR_TCE' : KVM_CAP_SPAPR_TCE,
        'KVM_CAP_PPC_SMT' : KVM_CAP_PPC_SMT,
        'KVM_CAP_PPC_RMA' : KVM_CAP_PPC_RMA,
        'KVM_CAP_MAX_VCPUS' : KVM_CAP_MAX_VCPUS,
        'KVM_CAP_PPC_HIOR' : KVM_CAP_PPC_HIOR,
        'KVM_CAP_PPC_PAPR' : KVM_CAP_PPC_PAPR,
        'KVM_CAP_SW_TLB' : KVM_CAP_SW_TLB,
        'KVM_CAP_ONE_REG' : KVM_CAP_ONE_REG,
        'KVM_CAP_S390_GMAP' : KVM_CAP_S390_GMAP,
        'KVM_CAP_TSC_DEADLINE_TIMER' : KVM_CAP_TSC_DEADLINE_TIMER,
        'KVM_CAP_S390_UCONTROL' : KVM_CAP_S390_UCONTROL,
        'KVM_CAP_SYNC_REGS' : KVM_CAP_SYNC_REGS,
        'KVM_CAP_PCI_2_3' : KVM_CAP_PCI_2_3,
        'KVM_CAP_KVMCLOCK_CTRL' : KVM_CAP_KVMCLOCK_CTRL,
        'KVM_CAP_SIGNAL_MSI' : KVM_CAP_SIGNAL_MSI,
        'KVM_CAP_PPC_GET_SMMU_INFO' : KVM_CAP_PPC_GET_SMMU_INFO,
        'KVM_CAP_S390_COW' : KVM_CAP_S390_COW,
        'KVM_CAP_PPC_ALLOC_HTAB' : KVM_CAP_PPC_ALLOC_HTAB,
        'KVM_CAP_READONLY_MEM' : KVM_CAP_READONLY_MEM,
        'KVM_CAP_IRQFD_RESAMPLE' : KVM_CAP_IRQFD_RESAMPLE,
        'KVM_CAP_PPC_BOOKE_WATCHDOG' : KVM_CAP_PPC_BOOKE_WATCHDOG,
        'KVM_CAP_PPC_HTAB_FD' : KVM_CAP_PPC_HTAB_FD,
        'KVM_CAP_S390_CSS_SUPPORT' : KVM_CAP_S390_CSS_SUPPORT,
        'KVM_CAP_PPC_EPR' : KVM_CAP_PPC_EPR,
        'KVM_CAP_ARM_PSCI' : KVM_CAP_ARM_PSCI,
        'KVM_CAP_ARM_SET_DEVICE_ADDR' : KVM_CAP_ARM_SET_DEVICE_ADDR,
        'KVM_CAP_DEVICE_CTRL' : KVM_CAP_DEVICE_CTRL,
        'KVM_CAP_IRQ_MPIC' : KVM_CAP_IRQ_MPIC,
        'KVM_CAP_PPC_RTAS' : KVM_CAP_PPC_RTAS,
        'KVM_CAP_IRQ_XICS' : KVM_CAP_IRQ_XICS,
        'KVM_CAP_HYPERV_TIME' : KVM_CAP_HYPERV_TIME,
        'KVM_CAP_IOAPIC_POLARITY_IGNORED' : KVM_CAP_IOAPIC_POLARITY_IGNORED,
    }
