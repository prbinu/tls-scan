#!/bin/bash

# download and build all dependent packages
./bootstrap.sh

# configure tls-scan
./configure --prefix=${PWD}/build-root

# make
make
make install

echo '>>> Complete'

