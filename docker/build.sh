#!/bin/bash
set -ex
. /etc/os-release
readonly HOST_DIR=$(realpath ..)
podman build -f Dockerfile.${ID} -v ${HOST_DIR}:/ulpatch --tag ${ID}-ulpatch
