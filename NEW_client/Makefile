new_client: echo_client.c 
	gcc -o new_client echo_client.c -lssl -lcrypto -lresolv -pthread -DMODE=1

tls_client: echo_client_active.c
	gcc -o tls_client echo_client_active.c -lssl -lcrypto -lresolv -pthread -DMODE=0

pas_client: echo_client_passive.c 
	gcc -o pas_client echo_client_passive.c -lssl -lcrypto -lresolv -pthread -DMODE=1

time_client: echo_client_passive_time.c 
	gcc -o time_client echo_client_passive_time.c  -lssl -lcrypto -lresolv -pthread -DMODE=1

act_client: echo_client_active.c 
	gcc -o act_client echo_client_active.c -lssl -lcrypto -lresolv -pthread -DMODE=1

all: pas_client time_client act_client tls_client

clean:
	rm pas_client time_client act_client tls_client
