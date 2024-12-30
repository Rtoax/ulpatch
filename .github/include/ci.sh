#!/bin/bash
set -e

BUILD_DIR="build-ci"

cmake -B ${BUILD_DIR}
tree -d ${BUILD_DIR}
make -C ${BUILD_DIR} -j$(nproc)
sudo make -C ${BUILD_DIR} install

ulpatch --info
