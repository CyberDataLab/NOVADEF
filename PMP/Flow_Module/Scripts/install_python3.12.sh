apt update
apt install -y software-properties-common

add-apt-repository -y ppa:deadsnakes/ppa
apt update

# Installing Python 3.12 + venv
apt install -y python3.12 python3.12-venv python3.12-dev
