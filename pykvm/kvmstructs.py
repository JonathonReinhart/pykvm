import ctypes
from ctypes import Structure, Union, c_uint8, c_uint16, c_uint32, c_uint64

class kvm_regs(Structure):
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




class kvm_segment(Structure):
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


class kvm_dtable(Structure):
    _fields_ = [
        ('base',        c_uint64),
        ('limit',       c_uint16),
        ('padding',     c_uint16 * 3),
    ]

    def __str__(self):
        return '    Base: 0x{:016X}  Limit: 0x{:04X}'.format(self.base, self.limit)

KVM_NR_INTERRUPTS = 256

class kvm_sregs(Structure):
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

def mkstruct(*fields):
    # http://stackoverflow.com/questions/357997
    return type('', (Structure,), {"_fields_": fields})

class kvm_debug_exit_arch__x86(Structure):
    _fields_ = [
        ('exception',       c_uint32),
        ('pad',             c_uint32),
        ('pc',              c_uint64),
        ('dr6',             c_uint64),
        ('dr7',             c_uint64),
    ]

kvm_debug_exit_arch = kvm_debug_exit_arch__x86

class kvm_run_exit_info_union(Union):
    _fields_ = [
        # KVM_EXIT_UNKNOWN
        ('hw',  mkstruct(
            ('hardware_exit_reason', c_uint64),
            )),
        # KVM_EXIT_FAIL_ENTRY
        ('fail_entry', mkstruct(
            ('hardware_entry_failure_reason', c_uint64),
            )),
        # KVM_EXIT_EXCEPTION
        ('ex', mkstruct(
            ('exception',   c_uint32),
            ('error_code',  c_uint32),
            )),
        # KVM_EXIT_IO
        ('io', mkstruct(
            ('direction',   c_uint8),
            ('size',        c_uint8),   # bytes
            ('port',        c_uint16),
            ('count',       c_uint32),
            ('data_offset', c_uint64),  # relative to kvm_run start
            )),
        ('debug', mkstruct(
            ('arch',        kvm_debug_exit_arch),
            )),
        # KVM_EXIT_MMIO
        ('mmio', mkstruct(
            ('phys_addr',   c_uint64),
            ('data',        c_uint8 * 8),
            ('len',         c_uint32),
            ('is_write',    c_uint8),
            )),
        # KVM_EXIT_HYPERCALL
        ('hypercall', mkstruct(
            ('nr',          c_uint64),
            ('args',        c_uint64 * 6),
            ('ret',         c_uint64),
            ('longmode',    c_uint32),
            ('pad',         c_uint32),
            )),
        # KVM_EXIT_TPR_ACCESS
        ('tpr_access', mkstruct(
            ('rip',         c_uint64),
            ('is_write',    c_uint32),
            ('pad',         c_uint32),
            )),
        # KVM_EXIT_INTERNAL_ERROR
        ('internal', mkstruct(
            ('suberror',    c_uint32),
            ('ndata',       c_uint32),
            ('data',        c_uint64 * 16),
            )),
        # KVM_EXIT_SYSTEM_EVENT
        ('system_event', mkstruct(
            ('type',        c_uint32),
            ('flags',       c_uint64),
            )),

        # Fix the size of the union.
        ('padding',         c_uint8 * 256),
    ]


class kvm_sync_regs__x86(Structure):
    _fields_ = [ ]

kvm_sync_regs = kvm_sync_regs__x86

class kvm_shared_regs_union(Union):
    _fields_ = [
        ('regs',            kvm_sync_regs),
        ('padding',         c_uint8 * 1024),
    ]

class kvm_run(Structure):
    _anonymous_ = ['_exit_info']
    _fields_ = [
        # in
        ('request_interrupt_window',        c_uint8),
        ('padding1',                        c_uint8 * 7),

        # out
        ('exit_reason',                     c_uint32),
        ('ready_for_interrupt_injection',   c_uint8),
        ('if_flag',                         c_uint8),
        ('padding2',                        c_uint8 * 2),

        #  in (pre_kvm_run), out (post_kvm_run)
        ('cr8',                             c_uint64),
        ('apic_base',                       c_uint64),

        # (actually an anonymous union)
        ('_exit_info',                      kvm_run_exit_info_union),

        # shared registers between kvm and userspace.
        ('kvm_valid_regs',                  c_uint64),
        ('kvm_dirty_regs',                  c_uint64),
        ('s',                               kvm_shared_regs_union),
    ]

    KVM_EXIT_IO_IN  = 0
    KVM_EXIT_IO_OUT = 1



class kvm_userspace_memory_region(Structure):
    _fields_ = [
        ('slot',            c_uint32),
        ('flags',           c_uint32),
        ('guest_phys_addr', c_uint64),
        ('memory_size',     c_uint64),
        ('userspace_addr',  c_uint64),
    ]

    KVM_MEM_LOG_DIRTY_PAGES = (1<<0)
    KVM_MEM_READONLY        = (1<<1)


class kvm_guest_debug_arch_x86(Structure):
    _fields_ = [
        ('debugreg',        c_uint64 * 8),
    ]

kvm_guest_debug_arch = kvm_guest_debug_arch_x86

class kvm_guest_debug(Structure):
    _fields_ = [
        ('control',         c_uint32),
        ('pad',             c_uint32),
        ('arch',            kvm_guest_debug_arch),
    ]
