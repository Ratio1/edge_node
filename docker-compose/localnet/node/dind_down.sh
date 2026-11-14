#!/bin/sh
# Release the loop devices a localnet node's container apps left in the host kernel (test bed only).
#
# The container app runner gives each fixed-size volume (and its always-on /r1en_system volume) an
# ext4 image file in the node's data folder, attached to a loop device and mounted. Mounts disappear
# with the node container; a loop device does not: it stays bound to its image file on the host
# until it is detached. "down" kills each node that runs Docker, then runs this script in a
# throwaway container that has that node's data volume at the same path, on the localnet network.
# `losetup -j` matches a loop device by the inode of its image file, so only devices of this node's
# own images are detached, never another loop device of the host.
set -u

DATA=${1:-/edge_node/_local_cache}
detached=0
left=0
# Every image file the runner created for this node (fixed_volumes/images/<volume>.img).
for img in $(find "$DATA" -path '*/fixed_volumes/images/*.img' 2>/dev/null); do
  # Each loop device still bound to that image file, by device and inode.
  for dev in $(losetup -j "$img" | cut -d: -f1); do
    # Detach it; a device still mounted somewhere is detached by the kernel when that mount ends.
    if losetup -d "$dev"; then
      detached=$((detached + 1))
    fi
  done
  # Count what is still bound to the image after the detach.
  left=$((left + $(losetup -j "$img" | grep -c .)))
done
echo "TEARDOWN detached=$detached left=$left"
