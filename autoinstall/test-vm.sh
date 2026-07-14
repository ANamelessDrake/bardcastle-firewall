#!/usr/bin/env bash
# Boot the custom autoinstall ISO in a QEMU VM for testing.
# No USB flashing needed — iterate in seconds.
#
# Usage: ./autoinstall/test-vm.sh [build] [bios]
#   - Without args: boots existing ISO in UEFI mode (matches the appliance)
#   - "build": rebuilds ISO first, then boots
#   - "bios":  boots via legacy BIOS instead of UEFI
#
# UEFI is the default because the target appliance (CWWK N100) is UEFI-only.
# The BIOS and UEFI boot paths of the ISO are completely independent —
# always test the one the real hardware will use.
#
# Press Ctrl+A then X to exit QEMU.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
ISO="$PROJECT_DIR/bardcastle-fw-autoinstall.iso"
DISK="$PROJECT_DIR/test-vm-disk.qcow2"
OVMF_VARS_LOCAL="$PROJECT_DIR/test-vm-ovmf-vars.fd"

BOOT_MODE="uefi"
DO_BUILD=""
for arg in "$@"; do
    case "$arg" in
        build) DO_BUILD=1 ;;
        bios)  BOOT_MODE="bios" ;;
        *) echo "Unknown argument: $arg (expected 'build' and/or 'bios')" >&2; exit 1 ;;
    esac
done

# Rebuild ISO if requested
if [[ -n "$DO_BUILD" ]]; then
    echo "Rebuilding ISO..."
    sudo "$SCRIPT_DIR/build-iso.sh"
    echo ""
fi

if [[ ! -f "$ISO" ]]; then
    echo "Error: ISO not found: $ISO" >&2
    echo "Run: sudo ./autoinstall/build-iso.sh" >&2
    exit 1
fi

# Locate OVMF firmware (paths vary by distro)
UEFI_ARGS=()
if [[ "$BOOT_MODE" == "uefi" ]]; then
    OVMF_CODE=""
    OVMF_VARS=""
    for pair in \
        "/usr/share/edk2/ovmf/OVMF_CODE.fd /usr/share/edk2/ovmf/OVMF_VARS.fd" \
        "/usr/share/OVMF/OVMF_CODE_4M.fd /usr/share/OVMF/OVMF_VARS_4M.fd" \
        "/usr/share/OVMF/OVMF_CODE.fd /usr/share/OVMF/OVMF_VARS.fd" \
        "/usr/share/edk2/x64/OVMF_CODE.4m.fd /usr/share/edk2/x64/OVMF_VARS.4m.fd"; do
        code="${pair% *}"; vars="${pair#* }"
        if [[ -f "$code" && -f "$vars" ]]; then
            OVMF_CODE="$code"
            OVMF_VARS="$vars"
            break
        fi
    done

    if [[ -z "$OVMF_CODE" ]]; then
        echo "Error: OVMF UEFI firmware not found." >&2
        echo "  Fedora: sudo dnf install edk2-ovmf" >&2
        echo "  Ubuntu: sudo apt install ovmf" >&2
        echo "Or run with 'bios' to test the legacy boot path instead." >&2
        exit 1
    fi

    # Writable per-VM copy of the NVRAM vars (stores boot entries)
    if [[ ! -f "$OVMF_VARS_LOCAL" ]]; then
        cp "$OVMF_VARS" "$OVMF_VARS_LOCAL"
    fi

    UEFI_ARGS=(
        -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE"
        -drive if=pflash,format=raw,file="$OVMF_VARS_LOCAL"
    )
fi

# Create a virtual disk if it doesn't exist (or recreate for fresh install)
if [[ -f "$DISK" ]]; then
    read -p "Existing VM disk found. Delete and start fresh? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -f "$DISK"
        rm -f "$OVMF_VARS_LOCAL"   # stale NVRAM boot entries point at the old install
        if [[ "$BOOT_MODE" == "uefi" ]]; then
            cp "$OVMF_VARS" "$OVMF_VARS_LOCAL"
        fi
    fi
fi

if [[ ! -f "$DISK" ]]; then
    echo "Creating 8GB virtual disk..."
    qemu-img create -f qcow2 "$DISK" 8G
fi

echo ""
echo "=== Booting VM ==="
echo "  ISO:  $ISO"
echo "  Disk: $DISK"
echo "  Boot: $BOOT_MODE"
echo "  RAM:  2GB"
echo "  NICs: 2 (virtio)"
echo ""
echo "  Ctrl+A then X to exit QEMU"
echo ""

# Boot the VM
# -m 2G          : 2GB RAM
# -smp 4         : 4 cores
# -nic x2        : two NICs to simulate WAN/LAN
# -nographic     : console output in terminal (no GUI window needed)
qemu-system-x86_64 \
    -m 2G \
    -smp 4 \
    -enable-kvm \
    -cpu host \
    "${UEFI_ARGS[@]}" \
    -drive file="$DISK",format=qcow2,if=virtio \
    -cdrom "$ISO" \
    -boot d \
    -nic user,model=virtio \
    -nic user,model=virtio \
    -nographic \
    -serial mon:stdio
