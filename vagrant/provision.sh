set -o errexit
set -o pipefail
set -o nounset
shopt -s failglob
set -o xtrace

export DEBIAN_FRONTEND=noninteractive

add-apt-repository ppa:deadsnakes/ppa

apt-get update

apt-get install -y git python3.5 python3.6

# install awscli and awsebcli under python 3
curl -O https://bootstrap.pypa.io/get-pip.py
python get-pip.py

pip install tox

# install domain certificate if available
cp /vagrant/domain.crt /usr/local/share/ca-certificates/domain.crt || echo COULD NOT COPY DOMAIN TRUST
ls /usr/local/share/ca-certificates/domain.crt && update-ca-certificates
rm -f /etc/profile.d/REQUESTS_CA_BUNDLE.sh
ls /usr/local/share/ca-certificates/domain.crt && echo 'export REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt' > /etc/profile.d/REQUESTS_CA_BUNDLE.sh
