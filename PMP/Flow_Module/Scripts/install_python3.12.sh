apt update
apt install -y software-properties-common

# Añadir PPA con versiones nuevas de Python
add-apt-repository -y ppa:deadsnakes/ppa
apt update

# Instalar Python 3.12 + venv (necesario para crear entornos)
apt install -y python3.12 python3.12-venv python3.12-dev
