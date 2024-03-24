Welcome to the ztls Project
==============================
The ztls is a project that provides example servers and clients that perform ztls handshake using ztlslib.
ztlslib (github.com/swlim02/ztlslib) is a library that implements ZTLS handshake based on OpenSSL. ZTLS leverages DNS to establish secure sessions with 0-RTT. For details, see 'ZTLS: A DNS-based Approach to Zero Round Trip Delay in TLS handshake' published in THE WEB CONFERENCE 2023.

# How to compile
> make ztls_client
> make tls_client
> make server

# How to run 
> ./server [port]
> ./client [domain_address] [port]

# Prerequisite
intstall github.com/swlim02/ztlslib

# TroubleShooting
1. add environment variables
export LD_LIBRARY_PATH=/usr/local/lib

# Environment Setup
This program requires several DNS records. See an_example_of_DNSzonefile_for_ZTLS file for environment setup.
