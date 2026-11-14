#!/bin/sh
# Start a localnet node that runs its own Docker daemon, as a production node does (test bed only).
#
# Production runs the node image with --privileged and EE_DD=1: the image entrypoint
# (/usr/local/bin/entrypoint.sh) starts dockerd inside the node container, then the node. Container
# apps run in that inner daemon, and their fixed-size volumes are loop devices the node mounts itself.
# This script runs the same image entrypoint with two steps in front of it:
#   1. the isolation guard, so that no Docker daemon ever runs in a container that can reach a public
#      network (the node's own launcher runs the guard again before any node code);
#   2. on a cgroup v2 host with a private cgroup namespace, the processes already running are moved
#      into a child group, so that the inner daemon can hand controllers to the containers it starts.
#      Production uses --cgroupns=host instead, which would make the inner daemon write into the
#      host's own cgroup tree.
set -eu

# Refuse to start the inner daemon unless this container is provably cut off (exit code 97 otherwise).
/opt/python/bin/python3 -I /opt/localnet/node/guard.py

if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
  # A child group for the processes of this container: cgroup v2 lets a group hand controllers to its
  # children only while it holds no process itself.
  mkdir -p /sys/fs/cgroup/init
  # Move every process of the container's root group into that child group, one pid per write.
  xargs -rn1 < /sys/fs/cgroup/cgroup.procs > /sys/fs/cgroup/init/cgroup.procs || :
  # Enable every available controller for the child groups the inner daemon creates for its containers.
  sed -e 's/ / +/g' -e 's/^/+/' < /sys/fs/cgroup/cgroup.controllers > /sys/fs/cgroup/cgroup.subtree_control
fi

# The production entrypoint of the image: starts dockerd (EE_DD=1), waits for it, then runs "$@".
exec /usr/local/bin/entrypoint.sh "$@"
