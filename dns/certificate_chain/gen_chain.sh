#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 algorithm"
    exit 1
fi

file1=$1


# your_command_here를 사용할 실제 명령어로 변경

# generate self-signed RootCA certificate
openssl req -x509 -new -newkey "$file1" -keyout "$file1"_CA.key -out "$file1"_CA.crt -nodes -subj "/CN=ESPLAB_CA" -days 365

# generate ICA_1 certificate
openssl genpkey -algorithm "$file1" -out "$file1"_ICA_1.key
openssl req -new -newkey "$file1" -keyout "$file1"_ICA_1.key -out "$file1"_ICA_1.csr -nodes -subj "/CN=ICA_1"
openssl x509 -req -in "$file1"_ICA_1.csr -out "$file1"_ICA_1.crt -CA "$file1"_CA.crt -CAkey "$file1"_CA.key -CAcreateserial -days 365

# generate ICA_2 certificate
openssl genpkey -algorithm "$file1" -out "$file1"_ICA_2.key
openssl req -new -newkey "$file1" -keyout "$file1"_ICA_2.key -out "$file1"_ICA_2.csr -nodes -subj "/CN=ICA_2"
openssl x509 -req -in "$file1"_ICA_2.csr -out "$file1"_ICA_2.crt -CA "$file1"_ICA_1.crt -CAkey "$file1"_ICA_1.key -CAcreateserial -days 365

# generate Server certificate
openssl genpkey -algorithm "$file1" -out "$file1"_srv.key
openssl req -new -newkey "$file1" -keyout "$file1"_srv.key -out "$file1"_srv.csr -nodes -subj "/CN=ESPLAB_Server"
openssl x509 -req -in "$file1"_srv.csr -out "$file1"_srv.crt -CA "$file1"_ICA_2.crt -CAkey "$file1"_ICA_2.key -CAcreateserial -days 365

# combine 3 certificate without root CA
cat "$file1"_srv.crt "$file1"_ICA_2.crt "$file1"_ICA_1.crt > "$file1"_chain.crt
#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 algorithm"
    exit 1
fi

file1=$1


# your_command_here를 사용할 실제 명령어로 변경

# generate self-signed RootCA certificate
openssl req -x509 -new -newkey "$file1" -keyout "$file1"_CA.key -out "$file1"_CA.crt -nodes -subj "/CN=ESPLAB_CA" -days 365

# generate ICA_1 certificate
openssl genpkey -algorithm "$file1" -out "$file1"_ICA_1.key
openssl req -new -newkey "$file1" -keyout "$file1"_ICA_1.key -out "$file1"_ICA_1.csr -nodes -subj "/CN=ICA_1"
openssl x509 -req -in "$file1"_ICA_1.csr -out "$file1"_ICA_1.crt -CA "$file1"_CA.crt -CAkey "$file1"_CA.key -CAcreateserial -days 365

# generate ICA_2 certificate
openssl genpkey -algorithm "$file1" -out "$file1"_ICA_2.key
openssl req -new -newkey "$file1" -keyout "$file1"_ICA_2.key -out "$file1"_ICA_2.csr -nodes -subj "/CN=ICA_2"
openssl x509 -req -in "$file1"_ICA_2.csr -out "$file1"_ICA_2.crt -CA "$file1"_ICA_1.crt -CAkey "$file1"_ICA_1.key -CAcreateserial -days 365

# generate Server certificate
openssl genpkey -algorithm "$file1" -out "$file1"_srv.key
openssl req -new -newkey "$file1" -keyout "$file1"_srv.key -out "$file1"_srv.csr -nodes -subj "/CN=ESPLAB_Server"
openssl x509 -req -in "$file1"_srv.csr -out "$file1"_srv.crt -CA "$file1"_ICA_2.crt -CAkey "$file1"_ICA_2.key -CAcreateserial -days 365

openssl genpkey -algorithm "$file1" -out "$file1"_srv.key
openssl req -new -newkey "$file1" -keyout "$file1"_1chain_srv.key -out "$file1"_1chain_srv.csr -nodes -subj "/CN=ESPLAB_Server"
openssl x509 -req -in "$file1"_1chain_srv.csr -out "$file1"_1chain_srv.crt -CA "$file1"_ICA_1.crt -CAkey "$file1"_ICA_1.key -CAcreateserial -days 365

# combine 3 certificate without root CA
cat "$file1"_srv.crt "$file1"_ICA_2.crt "$file1"_ICA_1.crt > "$file1"_chain.crt
#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 algorithm"
    exit 1
fi

file1=$1


# your_command_here를 사용할 실제 명령어로 변경

# generate self-signed RootCA certificate
openssl req -x509 -new -newkey "$file1" -keyout "$file1"_CA.key -out "$file1"_CA.crt -nodes -subj "/CN=ESPLAB_CA" -days 365

# generate ICA_1 certificate
openssl genpkey -algorithm "$file1" -out "$file1"_ICA_1.key
openssl req -new -newkey "$file1" -keyout "$file1"_ICA_1.key -out "$file1"_ICA_1.csr -nodes -subj "/CN=ICA_1"
openssl x509 -req -in "$file1"_ICA_1.csr -out "$file1"_ICA_1.crt -CA "$file1"_CA.crt -CAkey "$file1"_CA.key -CAcreateserial -days 365

# generate ICA_2 certificate
openssl genpkey -algorithm "$file1" -out "$file1"_ICA_2.key
openssl req -new -newkey "$file1" -keyout "$file1"_ICA_2.key -out "$file1"_ICA_2.csr -nodes -subj "/CN=ICA_2"
openssl x509 -req -in "$file1"_ICA_2.csr -out "$file1"_ICA_2.crt -CA "$file1"_ICA_1.crt -CAkey "$file1"_ICA_1.key -CAcreateserial -days 365

# generate Server certificate
openssl genpkey -algorithm "$file1" -out "$file1"_srv.key
openssl req -new -newkey "$file1" -keyout "$file1"_srv.key -out "$file1"_srv.csr -nodes -subj "/CN=ESPLAB_Server"
openssl x509 -req -in "$file1"_srv.csr -out "$file1"_srv.crt -CA "$file1"_ICA_2.crt -CAkey "$file1"_ICA_2.key -CAcreateserial -days 365

# combine 3 certificate without root CA
cat "$file1"_srv.crt "$file1"_ICA_2.crt "$file1"_ICA_1.crt > "$file1"_2ICA_chain.crt
cat "$file1"_1chain_srv.crt "$file1"_ICA_1.crt > "$file1"_1ICA_chain.crt

