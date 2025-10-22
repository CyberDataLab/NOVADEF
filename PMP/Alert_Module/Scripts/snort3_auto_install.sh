#!/bin/bash

# Este script instala las dependencias necesarias y luego Snort3 en Ubuntu.

# Actualizar el sistema
echo "Actualizando el sistema..."
apt update -y #sudo
apt upgrade -y #sudo
#cd ~
# Instalación de las dependencias necesarias
echo "Instalando dependencias..."
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

# Instlar DAQ manualmente
echo "Instalando DAQ manualmente"
echo "**********************************************************************"
cd ~
git clone https://github.com/snort3/libdaq.git
cd libdaq
./bootstrap
./configure
make -j$(nproc)
make install #sudo
ldconfig #sudo

# Verificar si hwloc está instalado correctamente
echo "Verificando instalación de hwloc..."
if ! pkg-config --exists hwloc; then
    echo "Error: hwloc no encontrado. Instalación fallida."
    exit 1
fi

# Instalar libpcre2 manualmente si no está disponible
echo "Verificando instalación de libpcre2..."
if ! pkg-config --exists libpcre2; then
    echo "libpcre2 no encontrado, instalando desde el repositorio oficial..."
    git clone https://github.com/PCRE2Project/pcre2.git
    cd pcre2
    mkdir build && cd build
    cmake ..
    make -j$(nproc)
    make install #sudo
    ldconfig  # Actualizar la caché de bibliotecas dinámicas #sudo
    cd ~
fi

# Instalar el paquete de CMake más reciente si es necesario (CMake 3.18+)
echo "Verificando e instalando CMake..."
CMAKE_VERSION=$(cmake --version | head -n 1 | awk '{print $3}')
if [[ "$(printf '%s\n3.18' "$CMAKE_VERSION" | sort -V | head -n1)" != "3.18" ]]; then
    echo "Instalando la versión más reciente de CMake..."
    wget https://cmake.org/files/v3.20/cmake-3.20.1-linux-x86_64.sh
    bash cmake-3.20.1-linux-x86_64.sh --prefix=/usr/local --skip-license #sudo
    rm cmake-3.20.1-linux-x86_64.sh
fi

# Clonar e instalar Snort3
echo "Clonando el repositorio de Snort3..."
cd ~
git clone https://github.com/snort3/snort3.git
cd snort3
mkdir build
cd build
echo "Configurando Snort3..."
cmake ../ || { echo "Error en la configuración de CMake."; exit 1; }
echo "Compilando e instalando Snort3..."
make -j$(nproc) || { echo "Error en la compilación de Snort3."; exit 1; }
make install #sudo


# Comprobar que Snort3 detecta DAQ correctamente
echo "Verificación final de Snort3..."
if snort -V | grep -q "Using DAQ version"; then
    echo "¡Snort3 ha sido instalado exitosamente con DAQ!"
else
    echo "Error: Snort3 sigue sin detectar DAQ. Revisa la instalación manualmente."
    exit 1
fi
