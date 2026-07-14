#!/usr/bin/env bash
# Build a custom Ubuntu Server 24.04 autoinstall ISO with bardcastle-firewall
# baked in. Fully unattended — boot from USB and walk away.
#
# Usage: sudo ./build-iso.sh [path-to-ubuntu-iso]
#
# Requires: xorriso
# Works on Fedora, Ubuntu, Debian, Arch — no distro-specific GRUB packages
# needed. Boot images are extracted from the source Ubuntu ISO itself.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
SOURCE_ISO="${1:-$PROJECT_DIR/ubuntu-24.04.4-live-server-amd64.iso}"
OUTPUT_ISO="$PROJECT_DIR/bardcastle-fw-autoinstall.iso"
WORK_DIR="$(mktemp -d)"
MOUNT_DIR="$WORK_DIR/mnt"
ISO_DIR="$WORK_DIR/iso"
MBR_IMG="$WORK_DIR/mbr.img"
EFI_IMG="$WORK_DIR/efi.img"

cleanup() {
    echo "Cleaning up..."
    umount "$MOUNT_DIR" 2>/dev/null || true
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

# Check prerequisites
if [[ $EUID -ne 0 ]]; then
    echo "Error: run as root (sudo)." >&2
    exit 1
fi

if [[ ! -f "$SOURCE_ISO" ]]; then
    echo "Error: source ISO not found: $SOURCE_ISO" >&2
    echo "Download it first or pass the path as an argument." >&2
    exit 1
fi

if ! command -v xorriso &>/dev/null; then
    echo "Error: xorriso not found." >&2
    echo "  Fedora: sudo dnf install xorriso" >&2
    echo "  Ubuntu: sudo apt install xorriso" >&2
    exit 1
fi

echo "=== Bardcastle Firewall ISO Builder ==="
echo "Source ISO : $SOURCE_ISO"
echo "Output ISO : $OUTPUT_ISO"
echo ""

# Step 1: Extract boot images from the source ISO
echo "[1/6] Extracting boot images from source ISO..."

# Extract MBR (first 432 bytes)
dd if="$SOURCE_ISO" bs=1 count=432 of="$MBR_IMG" 2>/dev/null

# Extract hidden EFI partition image from the ISO
# Parse El Torito entry 2 (UEFI) to get LBA and size
EFI_LBA=$(xorriso -indev "$SOURCE_ISO" -report_el_torito plain 2>&1 \
    | grep "El Torito boot img :   2" | awk '{print $NF}')
EFI_BLOCKS=$(xorriso -indev "$SOURCE_ISO" -report_el_torito plain 2>&1 \
    | grep "El Torito img blks :   2" | awk '{print $NF}')

if [[ -z "$EFI_LBA" || -z "$EFI_BLOCKS" ]]; then
    echo "Error: could not find EFI boot image in source ISO." >&2
    exit 1
fi

# Both LBA and img blks are in 2048-byte ISO blocks
dd if="$SOURCE_ISO" bs=2048 skip="$EFI_LBA" count="$EFI_BLOCKS" of="$EFI_IMG" 2>/dev/null
echo "  MBR: extracted (432 bytes)"
echo "  EFI: extracted from LBA $EFI_LBA ($EFI_BLOCKS x 2048-byte blocks)"

# Step 2: Extract the ISO contents
echo "[2/6] Extracting ISO..."
mkdir -p "$MOUNT_DIR" "$ISO_DIR"
mount -o loop,ro "$SOURCE_ISO" "$MOUNT_DIR"
cp -a "$MOUNT_DIR"/. "$ISO_DIR"/
umount "$MOUNT_DIR"

# Step 3: Add autoinstall config
echo "[3/6] Adding autoinstall configuration..."
cp "$SCRIPT_DIR/user-data" "$ISO_DIR/user-data"
cp "$SCRIPT_DIR/meta-data" "$ISO_DIR/meta-data"

# Place the EFI image where xorriso can find it
mkdir -p "$ISO_DIR/boot/grub"
cp "$EFI_IMG" "$ISO_DIR/boot/grub/efi.img"

# Step 4: Build the web dashboard, then copy source into the ISO
echo "[4/6] Building web dashboard + copying source..."

# Build the SPA so the appliance ships static files (no Node on the appliance).
if command -v npm &>/dev/null; then
    ( cd "$PROJECT_DIR/webui/frontend" && npm ci --no-audit --no-fund && npm run build )
else
    echo "  WARNING: npm not found; the dashboard SPA will NOT be prebuilt." >&2
    echo "  Install Node.js to bake the dashboard into the ISO." >&2
fi

mkdir -p "$ISO_DIR/bardcastle-firewall"
for item in bardcastle templates docs webui autoinstall config.yaml requirements.txt setup.py README.md; do
    if [[ -e "$PROJECT_DIR/$item" ]]; then
        cp -a "$PROJECT_DIR/$item" "$ISO_DIR/bardcastle-firewall/"
    fi
done
# Do not ship node_modules; the appliance serves the prebuilt dist only.
rm -rf "$ISO_DIR/bardcastle-firewall/webui/frontend/node_modules"

# Remove md5sum file to prevent checksum errors from modified files
rm -f "$ISO_DIR/md5sum.txt"

# Step 5: Modify GRUB to trigger autoinstall
echo "[5/6] Configuring GRUB for autoinstall..."

# Modify GRUB config for BIOS boot
if [[ -f "$ISO_DIR/boot/grub/grub.cfg" ]]; then
    sed -i 's|linux\s\+/casper/vmlinuz\s*---|linux /casper/vmlinuz autoinstall cloud-config-url=/dev/null ds=nocloud\\;s=/cdrom/ ---|' \
        "$ISO_DIR/boot/grub/grub.cfg"

    # Set timeout to 5 seconds so it auto-boots
    sed -i 's/^set timeout=.*/set timeout=5/' "$ISO_DIR/boot/grub/grub.cfg"
fi

# Also modify the EFI GRUB config if separate
if [[ -f "$ISO_DIR/boot/grub/loopback.cfg" ]]; then
    sed -i 's|linux\s\+/casper/vmlinuz\s*---|linux /casper/vmlinuz autoinstall cloud-config-url=/dev/null ds=nocloud\\;s=/cdrom/ ---|' \
        "$ISO_DIR/boot/grub/loopback.cfg"
fi

# Step 6: Repack the ISO
echo "[6/6] Repacking ISO..."
xorriso -as mkisofs \
    -r -V "Bardcastle-FW" \
    -o "$OUTPUT_ISO" \
    -J -l \
    -b boot/grub/i386-pc/eltorito.img \
    -no-emul-boot -boot-load-size 4 -boot-info-table \
    --grub2-boot-info --grub2-mbr "$MBR_IMG" \
    -eltorito-alt-boot -e boot/grub/efi.img -no-emul-boot \
    -isohybrid-gpt-basdat \
    "$ISO_DIR"

# Change ownership to the user who ran sudo
if [[ -n "${SUDO_USER:-}" ]]; then
    chown "$SUDO_USER":"$SUDO_USER" "$OUTPUT_ISO"
fi

echo ""
echo "=== Done ==="
echo "Custom ISO: $OUTPUT_ISO"
echo "Size: $(du -h "$OUTPUT_ISO" | cut -f1)"
echo ""
echo "Flash to USB:"
echo "  sudo dd if=$OUTPUT_ISO of=/dev/sdX bs=4M conv=fsync status=progress 2>&1"
echo ""
echo "The install is fully unattended. Boot from USB and it will:"
echo "  1. Install Ubuntu Server 24.04 LTS (minimal)"
echo "  2. Set GRUB params to fix Bay Trail igb Tx hangs"
echo "  3. Create user 'admin' with SSH enabled"
echo "  4. Install bardcastle-fw CLI tool"
echo "  5. Reboot into a ready system"
echo ""
echo "After reboot, SSH in and run: sudo bardcastle-fw setup"
