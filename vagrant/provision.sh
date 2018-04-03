set -o errexit
set -o pipefail
set -o nounset
shopt -s failglob
set -o xtrace

export DEBIAN_FRONTEND=noninteractive

add-apt-repository ppa:deadsnakes/ppa

apt-get update

apt-get install -y python3.5 python3.6

# install awscli and awsebcli under python 3
curl -O https://bootstrap.pypa.io/get-pip.py
python get-pip.py

pip install tox
