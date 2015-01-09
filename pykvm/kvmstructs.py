import ctypes
from ctypes import c_uint8, c_uint16, c_uint32, c_uint64

class kvm_regs(ctypes.Structure):
    _fields_ = [
        ('rax',         c_uint64),
        ('rbx',         c_uint64),
        ('rcx',         c_uint64),
        ('rdx',         c_uint64),
        ('rsi',         c_uint64),
        ('rdi',         c_uint64),
        ('rsp',         c_uint64),
        ('rbp',         c_uint64),
        ('r8',          c_uint64),
        ('r9',          c_uint64),
        ('r10',         c_uint64),
        ('r11',         c_uint64),
        ('r12',         c_uint64),
        ('r13',         c_uint64),
        ('r14',         c_uint64),
        ('r15',         c_uint64),
        ('rip',         c_uint64),
        ('rflags',      c_uint64),
    ]

    def __str__(self):
        return '\n'.join((
            '  RAX:     0x{:016X}'.format(self.rax),
            '  RBX:     0x{:016X}'.format(self.rbx),
            '  RCX:     0x{:016X}'.format(self.rcx),
            '  RDX:     0x{:016X}'.format(self.rdx),
            '  RSI:     0x{:016X}'.format(self.rsi),
            '  RDI:     0x{:016X}'.format(self.rdi),
            '  RSP:     0x{:016X}'.format(self.rsp),
            '  RBP:     0x{:016X}'.format(self.rbp),
            '  R8:      0x{:016X}'.format(self.r8),
            '  R9:      0x{:016X}'.format(self.r9),
            '  R10:     0x{:016X}'.format(self.r10),
            '  R11:     0x{:016X}'.format(self.r11),
            '  R12:     0x{:016X}'.format(self.r12),
            '  R13:     0x{:016X}'.format(self.r13),
            '  R14:     0x{:016X}'.format(self.r14),
            '  R15:     0x{:016X}'.format(self.r15),
            '  RIP:     0x{:016X}'.format(self.rip),
            '  RFLAGS:  0x{:016X}'.format(self.rflags),
            ))




class kvm_segment(ctypes.Structure):
    _fields_ = [
        ('base',        c_uint64),
        ('limit',       c_uint32),
        ('selector',    c_uint16),
        ('type',        c_uint8),
        ('present',     c_uint8),
        ('dpl',         c_uint8),
        ('db',          c_uint8),
        ('s',           c_uint8),
        ('l',           c_uint8),
        ('g',           c_uint8),
        ('avl',         c_uint8),
        ('unusable',    c_uint8),
        ('padding',     c_uint8),
    ]

    def __str__(self):
        return '\n'.join((
            '    Base: 0x{:016X}  Limit: 0x{:08X}  Selector: 0x{:04X}  Type: 0x{:02X}'.format(
                self.base, self.limit, self.selector, self.type),
            '    Present: {}  DPL: {}  DB: {}  S: {}  L: {}  G: {}  AVL: {}  Unusable: {}'.format(
                self.present, self.dpl, self.db, self.s, self.l, self.g, self.avl, self.unusable),
            ))
                

class kvm_dtable(ctypes.Structure):
    _fields_ = [
        ('base',        c_uint64),
        ('limit',       c_uint16),
        ('padding',     c_uint16 * 3),
    ]

    def __str__(self):
        return '    Base: 0x{:016X}  Limit: 0x{:04X}'.format(self.base, self.limit)

KVM_NR_INTERRUPTS = 256

class kvm_sregs(ctypes.Structure):
    _fields_ = [
        ('cs',          kvm_segment),
        ('ds',          kvm_segment),
        ('es',          kvm_segment),
        ('fs',          kvm_segment),
        ('gs',          kvm_segment),
        ('ss',          kvm_segment),
        ('tr',          kvm_segment),
        ('ldt',         kvm_segment),
        ('gdt',         kvm_dtable),
        ('idt',         kvm_dtable),
        ('cr0',         c_uint64),
        ('cr2',         c_uint64),
        ('cr3',         c_uint64),
        ('cr4',         c_uint64),
        ('cr8',         c_uint64),
        ('efer',        c_uint64),
        ('apic_base',   c_uint64),
        ('interrupt_bitmap', c_uint64 * ((KVM_NR_INTERRUPTS + 63) / 64) ),
    ]

    def __str__(self):
        return '\n'.join((
            '  CS:', str(self.cs),
            '  DS:', str(self.ds),
            '  ES:', str(self.es),
            '  FS:', str(self.fs),
            '  GS:', str(self.gs),
            '  SS:', str(self.ss),
            '  TR:', str(self.tr),
            '  LDT:', str(self.ldt),
            '  CR0:         0x{:016X}'.format(self.cr0),
            '  CR2:         0x{:016X}'.format(self.cr2),
            '  CR3:         0x{:016X}'.format(self.cr3),
            '  CR4:         0x{:016X}'.format(self.cr4),
            '  CR8:         0x{:016X}'.format(self.cr8),
            '  EFER:        0x{:016X}'.format(self.efer),
            '  APIC Base:   0x{:016X}'.format(self.apic_base),
            ))
