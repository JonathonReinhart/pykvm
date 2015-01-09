import os
from fcntl import fcntl, ioctl

__all__ = ['Kvm']

class Kvm(object):
    KVM_GET_API_VERSION            = 0x0000AE00
    KVM_CREATE_VM                  = 0x0000AE01
    KVM_GET_MSR_INDEX_LIST         = 0xC004AE02

    def __init__(self):
        self.fd = os.open('/dev/kvm', os.O_RDWR)

        print 'API version:', self._get_api_version()

    def _get_api_version(self):
        return ioctl(self.fd, Kvm.KVM_GET_API_VERSION) 
