# pykvm
# https://github.com/JonathonReinhart/pykvm
# (C) 2015 Jonathon Reinhart

from kvmstructs import *

class KvmExit(object):
    # Exit reasons
    KVM_EXIT_UNKNOWN          = 0
    KVM_EXIT_EXCEPTION        = 1
    KVM_EXIT_IO               = 2
    KVM_EXIT_HYPERCALL        = 3
    KVM_EXIT_DEBUG            = 4
    KVM_EXIT_HLT              = 5
    KVM_EXIT_MMIO             = 6
    KVM_EXIT_IRQ_WINDOW_OPEN  = 7
    KVM_EXIT_SHUTDOWN         = 8
    KVM_EXIT_FAIL_ENTRY       = 9
    KVM_EXIT_INTR             = 10
    KVM_EXIT_SET_TPR          = 11
    KVM_EXIT_TPR_ACCESS       = 12
    KVM_EXIT_S390_SIEIC       = 13
    KVM_EXIT_S390_RESET       = 14
    KVM_EXIT_DCR              = 15
    KVM_EXIT_NMI              = 16
    KVM_EXIT_INTERNAL_ERROR   = 17
    KVM_EXIT_OSI              = 18
    KVM_EXIT_PAPR_HCALL       = 19
    KVM_EXIT_S390_UCONTROL    = 20
    KVM_EXIT_WATCHDOG         = 21
    KVM_EXIT_S390_TSCH        = 22
    KVM_EXIT_EPR              = 23

    def __init__(self):
        raise Exception('Use from_vcpu() factory method')

    @classmethod
    def from_vcpu(cls, vcpu, dt):
        subclasses = dict((c.code, c) for c in cls.__subclasses__())
        r = subclasses[vcpu.kvm_run.exit_reason](vcpu)
        r.dt = dt
        return r

    def __str__(self):
        return 'KVM Exit (dt = {:.06f} ms): '.format(self.dt * 1000) + self._getstr()


class KvmExitUnknown(KvmExit):
    code = KvmExit.KVM_EXIT_UNKNOWN

    def __init__(self, vcpu):
        self.hardware_exit_reason = vcpu.kvm_run.hw.hardware_exit_reason

    def _getstr(self):
        return 'Unknown reason. Hardware reason: 0x{:X}'.format(self.hardware_exit_reason)

class KvmExitException(KvmExit):
    code = KvmExit.KVM_EXIT_EXCEPTION

    def __init__(self, vcpu):
        self.exception = vcpu.kvm_run.ex.exception
        self.error_code = vcpud.kvm_run.ex.error_code

    def _getstr(self):
        return 'Exception: 0x{:X}, error code: 0x{:X}'.format(self.exception, self.error_code)

class KvmExitIo(KvmExit):
    code = KvmExit.KVM_EXIT_IO

    def __init__(self, vcpu):
        self.vcpu = vcpu

        io = vcpu.kvm_run.io
        self.is_write = io.direction == kvm_run.KVM_EXIT_IO_OUT
        self.size = io.size
        self.port = io.port
        self.count = io.count

        # TODO: Should the accessors deal with integers or strings?
        self.data = (c_uint8 * self.size).from_address(
                ctypes.addressof(vcpu.kvm_run) + io.data_offset)

    def _getstr(self):
        s = 'IO: {} port 0x{:X} ({} bytes)'.format(
                'Write to' if self.is_write else 'Read from',
                self.port, self.size)
        if self.is_write:
            s += '  Data: ' + self.get_data().encode('hex')
        return s

    def get_data(self):
        if not self.is_write:
            # TODO: Use KvmException
            raise Exception('Cannot get data from IO read')
        return str(bytearray(self.data))



    def set_data(self, data):
        if self.is_write:
            #TODO
            raise Exception('Cannot set data for IO write')
        if len(data) != self.size:
            # TODO
            raise Exception('data must be exactly {} bytes'.format(self.size))
        ctypes.memmove(self.data, data, len(data))


class KvmExitHlt(KvmExit):
    code = KvmExit.KVM_EXIT_HLT

    def __init__(self, vcpu):
        pass

    def _getstr(self):
        return 'Halted.'

class KvmExitFailEntry(KvmExit):
    code = KvmExit.KVM_EXIT_FAIL_ENTRY

    def __init__(self, vcpu):
        self.hardware_entry_failure_reason = vcpu.kvm_run.fail_entry.hardware_entry_failure_reason

    def _getstr(self):
        return 'Entry Failure. Hardware reason: 0x{:X}'.format(self.hardware_entry_failure_reason)

class KvmExitMmio(KvmExit):
    code = KvmExit.KVM_EXIT_MMIO

    def __init__(self, vcpu):
        m = vcpu.kvm_run.mmio
        self.phys_addr = m.phys_addr
        self.data = m.data
        self.len = m.len
        self.is_write = bool(m.is_write)

    def _getstr(self):
        return 'MMIO: {} 0x{:X} ({} bytes)'.format(
                'Write to' if self.is_write else 'Read from',
                self.phys_addr, self.len)

class KvmExitIntr(KvmExit):
    code = KvmExit.KVM_EXIT_INTR

    def __init__(self, vcpu):
        pass

    def _getstr(self):
        return 'Interrupted by signal.'

class KvmExitInternalError(KvmExit):
    code = KvmExit.KVM_EXIT_INTERNAL_ERROR

    def __init__(self, vcpu):
        i = vcpu.kvm_run.internal
        self.suberror = i.suberror
        self.data = i.data[:i.ndata]

    def _getstr(self):
        suberr_str = self.err_map.get(self.suberror)
        if not suberr_str:
            suberr_str = '0x{:X}'.format(self.suberror)
        s = 'Internal Error: {}'.format(suberr_str)
        s += '\nData:'
        for d in self.data:
            s += '\n   0x{:X}'.format(d)
        return s

    KVM_INTERNAL_ERROR_EMULATION    = 1
    KVM_INTERNAL_ERROR_SIMUL_EX     = 2
    KVM_INTERNAL_ERROR_DELIVERY_EV  = 3

    err_map = {
        KVM_INTERNAL_ERROR_EMULATION:   'Instruction emulation failed',
        KVM_INTERNAL_ERROR_SIMUL_EX:    'Unexpected simultaneous exceptions encountered',
        KVM_INTERNAL_ERROR_DELIVERY_EV: 'Unexpected vm-exit due to delivery event encountered',
    }
