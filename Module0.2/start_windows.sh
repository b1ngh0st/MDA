#!/bin/bash
qemu-system-x86_64 \
  -enable-kvm \
  -cpu host \
  -m 8G \
  -smp 4 \
  -drive file=win10_vm.qcow2,format=qcow2 \
  -cdrom Win10_22H2_English_x64v1.iso \
  -boot menu=on \
  -vga std \
  -device e1000,netdev=net0 \
  -netdev user,id=net0 \
  -display gtk