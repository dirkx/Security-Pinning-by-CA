#!/bin/sh

#  create-ca-and-server-certs.sh
#  Security Pinning by CA
#
# Copyright (c) 2013 Dirk-Willem van Gulik <dirkx@webweaving.org>,
#                       All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
DAYS=${DAYS:-10}
CNF=${SOURCE_ROOT}/openssl.cnf
HOSTNAME=localhost

# Bomb out on any non-zero exit.
set -e
mkdir -p "${DERIVED_FILES_DIR}"
cd "${DERIVED_FILES_DIR}"

# Step 1. (re)create the (self signed) root certificate
#
openssl req -config "${CNF}" \
    -new -x509 -keyout ca.key -out ca.pem -subj "/CN=Da Roots" -nodes -set_serial 1 -days $DAYS

# Step 2. create a sub CA - and sign with the root certificate
openssl req -config "${CNF}" \
    -new -keyout sub.key -out sub.csr -subj "/CN=Sub CA" -nodes -extensions v3_req
openssl x509 -extfile "${CNF}" \
    -req  -in sub.csr -CA ca.pem -CAkey ca.key -set_serial 2 -days $DAYS -out sub.pem  -extensions v3_ca

# Step 2. create a sub sub CA - and sign with the sun ca certificate
openssl req -config "${CNF}" \
    -new   -keyout subsub.key -out subsub.csr -subj "/CN=Sub Sub CA" -nodes -extensions v3_ca
openssl x509 -extfile "${CNF}" \
    -req  -in subsub.csr -CA sub.pem -CAkey sub.key -set_serial 3 -days $DAYS -out subsub.pem  -extensions v3_ca

# Step 3. create a server certificate
#
HOSTNAME=${HOSTNAME:-`hostname -f`}
openssl req -config "${CNF}" \
    -new -keyout server.key -out server.csr -subj "/CN=${HOSTNAME}" -nodes
openssl x509 -extfile "${CNF}" \
    -req -in server.csr -CA subsub.pem -CAkey subsub.key -set_serial 3 -days $DAYS -out server.pem  -extensions usr_cert

# Finally - we also create one for Evil Eve.
#
openssl req -config "${CNF}" \
    -new -x509 -keyout evil-ca.key -out evil-ca.pem -subj "/CN=Evil Roots" -nodes -set_serial 1 -days $DAYS
openssl req -config "${CNF}" \
    -new -keyout evil-sub.key -out evil-sub.csr -subj "/CN=Evil-Sub CA" -nodes -extensions v3_req
openssl x509 -extfile "${CNF}" \
    -req  -in evil-sub.csr -CA evil-ca.pem -CAkey evil-ca.key -set_serial 2 -days $DAYS \
    -out evil-sub.pem  -extensions v3_ca
openssl req -config "${CNF}" \
    -new -keyout evil-server.key -out evil-server.csr -subj "/CN=${HOSTNAME}/O=Evil Eve" -nodes
openssl x509 -extfile "${CNF}" \
    -req -in evil-server.csr -CA evil-sub.pem -CAkey evil-sub.key -set_serial 3 -days $DAYS \
    -out evil-server.pem  -extensions usr_cert

# Clean up the key material no longer needed. Clean up the requests
# rm ca.key sub.key subsub.key sub.csr subsub.csr server.csr

# Create the chain needed by the webserver. We intentionally
# also add the evil CA to this list. As that should not
# matter if things work as advertized.
#
cat subsub.pem sub.pem \
    evil-server.pem evil-sub.pem evil-ca.pem \
    > chain.pem

# Create the DER file which is hardcoded into the Pinned client
openssl x509 -in ca.pem -out ca.der -outform DER

cat <<EOM > proxy.conf
# Warning - this file is generated by the create-ca-and-server.sh
#           script in the 'CA and Certificates' section.
#
# Do not edit in place; instead edit the script and
# rebuild.
#
# Activate in apache with the command:
#
#   sudo ln -s "${DERIVED_FILES_DIR}"/proxy.conf \\
#                   /etc/apache2/users/proxy.conf"
#
# And then restart apache:
#
#   sudo apachectl restart
#
# Or by moving this file into /etc/apache2/users.
#

SetEnv CERTDIR "${DERIVED_FILES_DIR}"

Listen *:8443
<VirtualHost *:8443>
    SSLEngine On
    SSLCertificateFile "\${CERTDIR}/server.pem"
    SSLCertificateKeyFile "\${CERTDIR}/server.key"
    SSLCACertificateFile "\${CERTDIR}/chain.pem"

    ProxyPass / http://xkcd.com/
    ProxyPassReverse / http://xkcd.com/
</VirtualHost>

EOM