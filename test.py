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

    return 0

if __name__ == '__main__':
    sys.exit(main())
