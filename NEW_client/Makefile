new_client: echo_client.c 
	gcc -o new_client echo_client.c -lssl -lcrypto -lresolv -pthread -DMODE=1

tls_client: echo_client.c 
	gcc -o tls_client echo_client.c -lssl -lcrypto -lresolv -pthread -DMODE=0


all: new_client tls_client

clean:
	rm new_client tls_client
