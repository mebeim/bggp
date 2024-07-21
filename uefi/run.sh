#!/bin/bash
#
# @mebeim - 2024-07-10
#

set -e

function cleanup {
	rm -f "$TMP_OVMF_VARS"
}

ROOTFS=build

if ! [ -d "$ROOTFS" ]; then
	echo "ERROR: ./"$ROOTFS" directory not found!" >&2
	echo "Did you build EDK II first?" >&2
	echo "Are you rinning this script from the directory where it is located?" >&2
	exit 1
fi

# Delete $TMP_OVMF_VARS on exit / CTRL+C
trap cleanup EXIT

OVMF_VARS="$ROOTFS/OVMF_VARS.fd"
OVMF_CODE="$ROOTFS/OVMF_CODE.fd"
TMP_OVMF_VARS="$(mktemp /tmp/BGGP5_TMP_OVMF_VARS.XXXXXXXX)"

cp startup.nsh "$ROOTFS/startup.nsh"
cp "$OVMF_VARS" "$TMP_OVMF_VARS"

qemu-system-x86_64 \
	-machine q35 \
	-m 2G \
	-cpu max \
	-nographic \
	-no-reboot \
	-serial stdio \
	-monitor none \
	-drive if=pflash,format=raw,unit=0,file="$OVMF_CODE",readonly=on \
	-drive if=pflash,format=raw,unit=1,file="$TMP_OVMF_VARS" \
	-drive format=raw,file=fat:rw:"$ROOTFS" \
	-global driver=cfi.pflash01,property=secure,value=on \
	-nic user,model=virtio-net-pci
