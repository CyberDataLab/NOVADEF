#!/bin/bash

# This script installs the necessary dependencies and then Snort3 on Ubuntu.

echo "Updating the system..."
apt update -y
apt upgrade -y

echo "Installing dependencies..."
#sudo
apt install -y \
    build-essential \
    cmake \
    git \
    flex \
    bison \
    libpcap-dev \
    libdnet-dev \
    libluajit-5.1-dev \
    libssl-dev \
    libpcap-dev \
    libjson-c-dev \
    libyaml-dev \
    libcap-dev \
    libmnl-dev \
    libcurl4-openssl-dev \
    zlib1g-dev \
    pkg-config \
    liblzma-dev \
    python3-dev \
    python3-pip \
    python3-setuptools \
    libmagic-dev \
    gcc \
    g++ \
    autoconf \
    libtool \
    wget \
    make \
    libhwloc-dev \
    libdaq-dev 


echo "Installing DAQ manually"
echo "**********************************************************************"
cd ~
git clone https://github.com/snort3/libdaq.git
cd libdaq
./bootstrap
./configure
make -j$(nproc)
make install
ldconfig

echo "Verifying hwloc installation..."
if ! pkg-config --exists hwloc; then
    echo "Error: hwloc not found. Installation failed."
    exit 1
fi

echo "Checking libpcre2 installation..."
if ! pkg-config --exists libpcre2; then
    echo "libpcre2 not found, installing from the official repository..."
    git clone https://github.com/PCRE2Project/pcre2.git
    cd pcre2
    mkdir build && cd build
    cmake ..
    make -j$(nproc)
    make install
    ldconfig  # Update the dynamic library cache
    cd ~
fi

echo "Verifying and installing CMake..."
CMAKE_VERSION=$(cmake --version | head -n 1 | awk '{print $3}')
if [[ "$(printf '%s\n3.18' "$CMAKE_VERSION" | sort -V | head -n1)" != "3.18" ]]; then
    echo "Installing the latest version of CMake..."
    wget https://cmake.org/files/v3.20/cmake-3.20.1-linux-x86_64.sh
    bash cmake-3.20.1-linux-x86_64.sh --prefix=/usr/local --skip-license
    rm cmake-3.20.1-linux-x86_64.sh
fi

echo "Cloning the Snort3 repository..."
cd ~
git clone https://github.com/snort3/snort3.git
cd snort3
mkdir build
cd build
echo "Configuring Snort3..."
cmake ../ || { echo "Error in CMake configuration."; exit 1; }
echo "Compiling and installing Snort3..."
make -j$(nproc) || { echo "Error compiling Snort3."; exit 1; }
make install


# Verifying that Snort3 correctly detects DAQ
echo "Final verification of Snort3..."
if snort -V | grep -q "Using DAQ version"; then
    echo "Snort3 has been successfully installed with DAQ."
else
    echo "Error: Snort3 still fails to detect DAQ. Please check the installation manually."
    exit 1
fi
