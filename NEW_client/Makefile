new_client: echo_client.c 
	gcc -o new_client echo_client.c -lssl -lcrypto -lresolv -pthread -DMODE=1

all: new_client

clean:
	rm new_client
