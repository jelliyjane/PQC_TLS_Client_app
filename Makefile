ztls_client: echo_client.c 
	gcc -o ztls_client echo_client.c -lssl -lcrypto -lresolv -pthread -DMODE=1

test_client: echo_client_test.c 
	gcc -o test_client echo_client_test.c -lssl -lcrypto -lresolv -pthread -DMODE=1

test: test.c 
	gcc -o test test.c -lssl -lcrypto -lresolv -pthread -DMODE=1

new_ztls_client: new_echo_client.c
	gcc -o new_ztls_client new_echo_client.c -lssl -lcrypto -lresolv -pthread -DMODE=1

pqztls_echo_client: pqztls_echo_client.c
	gcc -o pqztls_echo_client pqztls_echo_client.c -lssl -lcrypto -lresolv -pthread -DMODE=1

tls_client: echo_client.c 
	gcc -o tls_client echo_client.c -lssl -lcrypto -lresolv -pthread -DMODE=0

client: client.c 
	gcc -o client client.c -lssl -lcrypto -lresolv -pthread -DMODE=0

server: echo_mpserv.c
	gcc -o server echo_mpserv.c -lssl -lcrypto

all: ztls_client tls_client server client new_ztls_client pqztls_echo_client test

clean:
	rm server tls_client ztls_client client new_ztls_client pqztls_echo_client test
