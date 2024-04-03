Welcome to the ztls Project
==============================
The ztls is a project that provides example servers and clients that perform ztls handshake using ztlslib.
ztlslib (github.com/swlim02/ztlslib) is a library that implements ZTLS handshake based on OpenSSL. ZTLS leverages DNS to establish secure sessions with 0-RTT. For details, see 'ZTLS: A DNS-based Approach to Zero Round Trip Delay in TLS handshake' published in THE WEB CONFERENCE 2023.

# How to compile
> make new_client

# How to run 
> ./server [port]
> ./client [domain_address], [domain_address2] ,,,  [port]
> ./ztls_client ns1.dil2.0.esplab.io ns1.dil2.1.esplab.io ns1.dil2.2.esplab.io ns1.dil2.3.esplab.io ns1.dil2.4.esplab.io ns1.dil2.5.esplab.io ns1.dil2.6.esplab.io ns1.esplab.io 12451
> DNS(US)  address 52.91.71.251

# Prerequisite client
intstall https://github.com/jelliyjane/openssl.git

# Prerequirement server 
install https://github.com/Thelookie/pqtls_server.git,  liboqs, oqsprovider

# TroubleShooting
1. add environment variables
export LD_LIBRARY_PATH=/usr/local/lib

2. add correct resolv.conf
sudo vim /etc/resolv.conf

# Environment Setup
This program requires several DNS records. See _
