#include "new_echo_client.h"

#include <arpa/nameser.h>
#include <netinet/in.h>
#include <resolv.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <netdb.h>


#define BUF_SIZE 10000
#define TXT_NUM 5
#define TLSA_NUM 7

#if MODE
int DNS = 1; 
#else
int DNS = 0;
#endif
// 0 = false; //normal TLS 1.3 
// 1 = true;  //ZTLS  
pthread_mutex_t mutex;

struct DNS_info{
    struct {
        time_t validity_period_not_before; //gmt unix time
        time_t validity_period_not_after;  //gmt unix time
        uint32_t dns_cache_id;
		uint32_t max_early_data_size;
    } DNSCacheInfo;
    struct {
        uint8_t *extension_type;
        uint16_t *extension_data;
    } EncryptedExtensions;
    struct {
        uint16_t group;
        EVP_PKEY *skey; // server's keyshare
    } KeyShareEntry;
    X509* cert; // server's cert
    struct {
        uint8_t certificate_request_context;
        uint16_t extensions;
    } CertRequest;
    struct {
        uint16_t signature_algorithms;
        unsigned char cert_verify[BUF_SIZE]; // signature
    } CertVerifyEntry;
} dns_info;

static void init_openssl();
static int load_dns_info2(struct DNS_info* dp, char* truncated_dnsmsg_out, char* dnsmsg, char* ztls_cert);
static SSL_CTX *create_context();
static void keylog_callback(const SSL* ssl, const char *line);
static size_t resolve_hostname(const char *host, const char *port, struct sockaddr_storage *addr);
static void configure_connection(SSL *ssl);
static void error_handling(char *message);
static int dns_info_add_cb(SSL *s, unsigned int ext_type,
                    unsigned int context,
                    const unsigned char **out,
                    size_t *outlen, X509 *x, size_t chainidx,
                    int *al, void *arg);

static void dns_info_free_cb(SSL *s, unsigned int ext_type,
                     unsigned int context,
                     const unsigned char *out,
                     void *add_arg);

static int ext_parse_cb(SSL *s, unsigned int ext_type,
                        const unsigned char *in,
                        size_t inlen, int *al, void *parse_arg);
static time_t is_datetime(const char *datetime);

static void init_tcp_sync(int argc, char *argv[], struct sockaddr_storage * addr, int sock, int * is_start);
static int tlsa_query(char *argv[], int tlsa_num, unsigned char pqtlsa_query_buffer[], int buffer_size,unsigned char ** tlsa_record_all, int * is_start);
static int txt_query(char *argv[], int txt_num, unsigned char txt_query_buffer[],unsigned char * txt_record_data);

unsigned char * hex_to_base64(unsigned char **hex_data, int* size, unsigned char hex[], int tlsa_num);


struct arg_struct {
	int argc;
	char ** argv;
	struct sockaddr_storage * addr;
	int sock;
	int * is_start;
};
struct arg_struct2 {
	int argc;
	char ** argv;
	int pqtlsa_num;
	unsigned char *pqtlsa_query_buffer;
	int buffer_size;
	int *pqtlsa_record_len;
	unsigned char ** pqtlsa_record_all;
	int * is_start;
};
struct arg_struct3{
	int argc;
	char ** argv;
	int txt_num;
	unsigned char *txt_query_buffer;
	unsigned char * txt_record_data;
};

static void *thread_init_tcp_sync(void* arguments)
{
	struct arg_struct* args = (struct arg_struct *) arguments;
	init_tcp_sync(args->argc, args->argv, args->addr, args->sock, args->is_start);
	pthread_exit(NULL);
}

static void *thread_tlsa_query(void* arguments)
{
	struct arg_struct2* args = (struct arg_struct2 *) arguments;
	int tlsa_len = tlsa_query(args->argv, args->pqtlsa_num, args->pqtlsa_query_buffer , args->buffer_size, args->pqtlsa_record_all, args->is_start);

	return (void *)tlsa_len;
}
static void *thread_txt_query(void* arguments)
{
	struct arg_struct3* args = (struct arg_struct3 *) arguments;
	txt_query(args->argv, args->txt_num, args->txt_query_buffer , args->txt_record_data);
	pthread_exit(NULL);
}

int main(int argc, char *argv[]){
	res_init();
	init_openssl();
	SSL_CTX *ctx = create_context();
	// static ctx configurations 
	SSL_CTX_load_verify_locations(ctx, "./dns/cert/dilithium2_crt.pem", "./dns/cert/");
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL); // SSL_VERIFY_NONE
	SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
	SSL_CTX_set_keylog_callback(ctx, keylog_callback);
	SSL * ssl = NULL;

    int sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(sock < 0){
        error_handling("socket() error");
    }

    struct sockaddr_storage addr;
    
    //txt
    int txt_num = TXT_NUM;
	unsigned char query_txt_buffer[txt_num][5000];
	char** txt_record_data;
	txt_record_data = (char**) malloc(sizeof(char*) * txt_num);
	for (int i = 0; i < txt_num; ++i)
	{
		txt_record_data[i]=(char*) malloc(sizeof(char)*5000);
	}
	
	//pqtlsa
	int tlsa_num = TLSA_NUM;
	unsigned char *pqtlsa_record_all[tlsa_num];
	char pqtlsa_record[BUF_SIZE];
	unsigned char query_pqtlsa_buffer[tlsa_num][4096];
	
	char hex_buffer[7000];
	
	int pqtlsa_len[tlsa_num];

	if(argc != 3+tlsa_num){
        printf("Usage : %s <port>\n please check number arguments now settled to %d\n", argv[0], TLSA_NUM+2);
        exit(1);
    }


	int is_start = -1;

    // log
    	printf("****start****\n");
	if (!DNS) {
    	struct timespec begin;
    	clock_gettime(CLOCK_MONOTONIC, &begin);
    	printf("start : %f\n",(begin.tv_sec) + (begin.tv_nsec) / 1000000000.0);
	}
	//=============================================================
	// Dynamic interaction start
	//=============================================================
    
	// get TXT record & dynamic ctx configurations for ZTLS
    if(DNS){
	    _res.options = _res.options | RES_USE_EDNS0 ; 	// use EDNS0 
	// to avoid TCP retry after UDP failure
		struct arg_struct args;
		args.argc = argc;
		args.argv = argv;
		args.addr = &addr;
		args.sock = sock;
		args.is_start = &is_start;

		pthread_t ptid;
		pthread_create(&ptid, NULL, &thread_init_tcp_sync,(void *) &args);

		struct arg_struct2 args2[tlsa_num];
		for (int i = 0; i < tlsa_num; ++i)
		{
			args2[i].argc = argc;
			args2[i].argv = argv;
			args2[i].pqtlsa_num = i+1;
			args2[i].pqtlsa_query_buffer = query_pqtlsa_buffer[i];
			args2[i].buffer_size = sizeof(query_pqtlsa_buffer[i]);
			args2[i].pqtlsa_record_len = pqtlsa_len+i;
			args2[i].pqtlsa_record_all = pqtlsa_record_all+i;
			args2[i].is_start = &is_start;
		}

		struct arg_struct3 args3[txt_num];
		for (int i = 0; i < txt_num; ++i)
		{
			args3[i].argc = argc;
			args3[i].argv = argv;
			args3[i].txt_num = i+1;
			args3[i].txt_query_buffer = query_txt_buffer[i];
			args3[i].txt_record_data = txt_record_data[i];
		}

		pthread_t ptid_pqtlsa[tlsa_num];

		pthread_mutex_init(&mutex,NULL);

		for (int i = 0; i < tlsa_num; ++i)
		{
			pthread_create(ptid_pqtlsa+i, NULL, &thread_tlsa_query, (void *)(args2+i));
		}
		// A thread is created when a program is executed, and is executed when a user triggers
		sleep(1);
		is_start = 1;
		pthread_t ptid_txt[txt_num];
		for (int i = 0; i < txt_num; ++i)
		{
			pthread_create(ptid_txt+i, NULL, &thread_txt_query, (void *)(args3+i));
		}
		
	    for (int i = 0; i < tlsa_num; ++i)
	    {
	    	pthread_join(ptid_pqtlsa[i], (void **)(pqtlsa_len+i));
	    }

	    for (int i = 0; i < txt_num; ++i)
	    {
		    pthread_join(ptid_txt[i], NULL);
	    }
	    //pthread_join(ptid_txt[0], NULL);

	pthread_mutex_destroy(&mutex);

	//printf("txt_record_data 1: %s\n", txt_record_data[0]);
	//printf("txt_record_data 2: %s\n", txt_record_data[1]);

	unsigned char * based64_out;
	based64_out = hex_to_base64(pqtlsa_record_all, pqtlsa_len,  hex_buffer, tlsa_num);
	// based64_out = hex_to_base64(tlsa2_record_all, tlsa2_len, hex_buffer);
	char newline2[4] = "\n";
	char* ztls_cert;
    ztls_cert = (char*) malloc(sizeof(char)*7000);
	//for(int j = 0; j < 916-64 ; j=j+64){ 908
	for(int j = 0; j < 5312 ; j=j+64){
		strncat(ztls_cert,based64_out+j,64);
		strcat(ztls_cert,newline2);
		//printf("hex_out_cert: %s", hex_out_cert);
	}
// fd
	//printf("ztls_cert: \n%s\n", ztls_cert);
	
	printf("\n\n");
	char *txt_record_all;
	txt_record_all = (char*) malloc (sizeof(char)*7000);
	char txt_record_except_signature[BUF_SIZE]="";
	for (int i = 0; i<txt_num; i++){
		strcat(txt_record_all,txt_record_data[i]);
	}
	/*
	strcat(txt_record_all,txt_record_data[0]);
	strcat(txt_record_all,txt_record_data[1]);
	strcat(txt_record_all,txt_record_data[2]);
	strcat(txt_record_all,txt_record_data[3]);
	strcat(txt_record_all,txt_record_data[4]);
	*/
	//printf("txt_record_all: %s\n", txt_record_all);
	for (int i = 0; i < txt_num; ++i)
	{
		free(txt_record_data[i]);
	}
	free(txt_record_data);
	//printf("txt_record_all:\n%s\n\n",txt_record_all);
        load_dns_info2(&dns_info, txt_record_except_signature, txt_record_all, ztls_cert); 
		SSL_CTX_add_custom_ext(ctx, 53, SSL_EXT_CLIENT_HELLO, dns_info_add_cb, dns_info_free_cb,NULL, NULL,NULL);// extentionTye = 53, Extension_data = dns_cache_id
    	if(dns_info.KeyShareEntry.group == 570){  // keyshare group : 0x001d(X25519)
			//SSL_CTX_set1_groups_list(ctx, "X25519");
			ssl = SSL_new(ctx);
		if(!SSL_set1_groups_list(ssl, "kyber512"))
			error_handling("fail to set kyber512");
			// for demo, we will add other groups later.
			// switch 
			// P-256, P-384, P-521, X25519, X448, ffdhe2048, ffdhe3072, ffdhe4096, ffdhe6144, ffdhe8192
    	}
		free(txt_record_all);

    	//ssl = SSL_new(ctx);
    	// dfSSL_set_wfd(ssl, DNS); // fd : 1 => ZTLS, fd : 0 => TLS 1.3
        printf("return of ssl set wfd: %d\n", SSL_set_wfd(ssl, DNS));
        // Check timestamp Valid
    	if(dns_info.DNSCacheInfo.validity_period_not_before < time(NULL) && dns_info.DNSCacheInfo.validity_period_not_after > time(NULL)){
        	printf("Valid Period\n");
    	}else{
       	 	printf("Not Valid Period\n");
    	}

		printf("return of server public key: %d\n",SSL_use_PrivateKey(ssl, dns_info.KeyShareEntry.skey)); // set server's keyshare // this function is modified 

        printf("return of ssl_use_certificate: %d\n", SSL_use_certificate(ssl, dns_info.cert)); // set sever's cert and verify cert_chain // this function is modified
    	if(dns_info.CertVerifyEntry.signature_algorithms == 2052)     //rsa pss rsae sha256 0x0804
		{
			strcat(txt_record_except_signature, "\n");
			//printf("txt_record_except_signature\n");
			//printf("%s",txt_record_except_signature );
			
			strcat(dns_info.CertVerifyEntry.cert_verify, "\n");
			//printf("\ndns_info.CertVerifyEntry.cert_verify\n");
			//printf("%s",dns_info.CertVerifyEntry.cert_verify );
			SSL_export_keying_material(ssl, (unsigned char*) txt_record_except_signature, 0, NULL, 0,
				 dns_info.CertVerifyEntry.cert_verify, BUF_SIZE, 0); // cert verify: signature of DNS cache info check. // this function is modified
		}	// for demo, we will only support rsa pss rsae_sha256 

		pthread_join(ptid, NULL);

    }else {
		is_start = 1;
		init_tcp_sync(argc, argv, &addr, sock, &is_start);
    	ssl = SSL_new(ctx);
    	SSL_set_wfd(ssl, DNS); // fd : 1 => ZTLS, fd : 0 => TLS 1.3
	}
	// threads join

    SSL_set_fd(ssl, sock);
    /*
     * handshake start
     */
    configure_connection(ssl); // SSL do handshake
    char message[BUF_SIZE];
    int str_len;
    struct timespec send_ctos, receive_ctos;

    if(!DNS){ // normal TLS 1.3
        memcpy(message, "hello\n", 6);
        
		SSL_write(ssl, message, strlen(message));
		clock_gettime(CLOCK_MONOTONIC, &send_ctos);
		printf("send : %s", message);
		printf("%f\n",(send_ctos.tv_sec) + (send_ctos.tv_nsec) / 1000000000.0);
				
		if((str_len = SSL_read(ssl, message, BUF_SIZE-1))<=0){
			printf("error\n");
		}
		message[str_len] = 0;
		clock_gettime(CLOCK_MONOTONIC, &receive_ctos);
		printf("Message from server: %s", message);
		printf("%f\n",(receive_ctos.tv_sec) + (receive_ctos.tv_nsec) / 1000000000.0);
    }
/* Temporarily deleted for performance measurement
    while(1){
        fputs("Input message(Q to quit): ", stdout);
        fgets(message, BUF_SIZE, stdin);

        if(!strcmp(message, "q\n") || !strcmp(message, "Q\n")){
            break;
        }

        SSL_write(ssl, message, strlen(message));
        clock_gettime(CLOCK_MONOTONIC, &send_ctos);
        printf("send : %s", message);
        printf("%f\n",(send_ctos.tv_sec) + (send_ctos.tv_nsec) / 1000000000.0);
        
	if((str_len = SSL_read(ssl, message, BUF_SIZE-1))<=0){
        	printf("error\n");
        }
        message[str_len] = 0;
        clock_gettime(CLOCK_MONOTONIC, &receive_ctos);
        printf("Message from server: %s", message);
        printf("%f\n",(receive_ctos.tv_sec) + (receive_ctos.tv_nsec) / 1000000000.0);
    }
*/
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    return 0;
}
static void init_tcp_sync(int argc, char *argv[], struct sockaddr_storage * addr, int sock, int * is_start) {
	while(*is_start < 0) { //for prototyping. next, use signal.
		//nothing
	}
    struct timespec begin1, begin2;
    clock_gettime(CLOCK_MONOTONIC, &begin1);
    printf("start A and AAAA DNS records query : %f\n",(begin1.tv_sec) + (begin1.tv_nsec) / 1000000000.0);
    printf("%s, %s\n",argv[argc - 2],argv[argc - 1]);
    //size_t len = resolve_hostname(argv[1], argv[3], addr);
    size_t len = resolve_hostname(argv[argc - 2], argv[argc - 1], addr);
    clock_gettime(CLOCK_MONOTONIC, &begin2);
    printf("complete A and AAAA DNS records query : %f\n",(begin2.tv_sec) + (begin2.tv_nsec) / 1000000000.0);
	if(connect(sock, (struct sockaddr*) addr, len) < 0){
        error_handling("connect() error!");
    }else{
    	clock_gettime(CLOCK_MONOTONIC, &begin2);
    	printf("complete TCP Sync : %f\n",(begin2.tv_sec) + (begin2.tv_nsec) / 1000000000.0);
    }
}

static int txt_query(char *argv[], int txt_num, unsigned char query_txt_buffer[], unsigned char * txt_record_all){
	
	ns_type type;
	type= ns_t_txt;
	ns_msg nsMsg;
	ns_rr rr;
	int response;
	struct timespec begin;
	clock_gettime(CLOCK_MONOTONIC, &begin);
	//is_start =1; //user trigger
	printf("start : %f\n",(begin.tv_sec) + (begin.tv_nsec) / 1000000000.0);
	clock_gettime(CLOCK_MONOTONIC, &begin);
	printf("start DNS TXT query: %f\n",(begin.tv_sec) + (begin.tv_nsec) / 1000000000.0);
	response = res_search(argv[txt_num], C_IN, type, query_txt_buffer, 4096);
	// log
	clock_gettime(CLOCK_MONOTONIC, &begin);
	printf("complete DNS TXT query : %f\n",(begin.tv_sec) + (begin.tv_nsec) / 1000000000.0);
	if (response < 0) {
		printf("Error looking up service: TXT %d\n", txt_num);
		return 0;
	} 

	ns_initparse(query_txt_buffer, response, &nsMsg);
	//ns_parserr(&nsMsg, ns_s_an, 0, &rr);
	u_char const *rdata = (u_char*)(ns_rr_rdata(rr)+1 );
	//*txt_record_all = (unsigned char*)rdata;
	int rr_count = ns_msg_count(nsMsg, ns_s_an);
	
    int offset = 0;

    int i;
    for (i = 0; i < rr_count; i++) {
        if (ns_parserr(&nsMsg, ns_s_an, i, &rr) == 0) {
            if (ns_rr_type(rr) == ns_t_txt) {
                u_char *rdata = ns_rr_rdata(rr);
                //printf("rdata: %s\n", rdata);
                int rdata_len = ns_rr_rdlen(rr);
                u_char *end = rdata + rdata_len;
                while (rdata < end) {
                    int txt_len = *rdata;
                    rdata++;
                    snprintf(txt_record_all + offset, 7000-offset, "%.*s ", txt_len, (char *)rdata);
                    offset += txt_len;
                    rdata += txt_len;
                }
            }
        } 
    }

    //strcat(*txt_record_all,'\0');
   // printf("txt_record_all: %s\n", txt_record_all);

}
static int tlsa_query(char *argv[], int tlsa_num, unsigned char query_buffer[], int buffer_size, unsigned char ** tlsa_record_all, int * is_start) {
	
	while(*is_start < 0) { //for prototyping. next, use signal.
		//nothing
	}
	printf("pqtlsa_num: %d\n", tlsa_num-1);
	char query_url[100] = "_443._udp.";
	strcat(query_url,argv[tlsa_num]);
	ns_type type2;
	type2 = ns_t_tlsa;
	ns_msg nsMsg;
	ns_rr rr;
	int response;
	
    	struct timespec begin;
    	clock_gettime(CLOCK_MONOTONIC, &begin);
    	printf("start DNS PQTLSA query: %f\n",(begin.tv_sec) + (begin.tv_nsec) / 1000000000.0);
		//printf("start DNS TLSA query:\n");
		response = res_search(query_url, C_IN, type2, query_buffer, buffer_size);
		// log
    	clock_gettime(CLOCK_MONOTONIC, &begin);
    	printf("complete DNS PQTLSA query : %f\n",(begin.tv_sec) + (begin.tv_nsec) / 1000000000.0);
		//printf("complete DNS TLSA query :\n");

	if (response < 0) {
		printf("Error looking up service: TLSA \n");
	}
	ns_initparse(query_buffer, response, &nsMsg);
	ns_parserr(&nsMsg, ns_s_an, 0, &rr);
	u_char const *rdata = (u_char*)(ns_rr_rdata(rr)+3);
	
	*tlsa_record_all = (unsigned char*)rdata;
	
	
	int len = ns_rr_rdlen(rr);
	return len-3;
}
static void init_openssl(){
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

static int load_dns_info2(struct DNS_info* dp, char* truncated_dnsmsg_out, char* dnsmsg, char * ztls_cert){
    BIO *bio_key, *bio_cert;
    char *tmp;
	//char publickey_prefix[5000] = "-----BEGIN PUBLIC KEY-----\n";
	char *publickey_prefix;
	publickey_prefix = (char *) malloc(sizeof(char)*6000);
	memset(publickey_prefix, 0, sizeof(char)*6000);
	strcpy(publickey_prefix, "-----BEGIN PUBLIC KEY-----\n");
	//printf("%s\n", publickey_prefix);
	

	char publickey_postfix[30] = "-----END PUBLIC KEY-----\n";
	char certificate_prefix[BUF_SIZE] = "-----BEGIN CERTIFICATE-----\n";
	char certificate_postfix[30] = "-----END CERTIFICATE-----\n";

	char *certificate_prefix2;
	certificate_prefix2 = (char *) malloc(sizeof(char)*7000);
	strcat(certificate_prefix2, "-----BEGIN CERTIFICATE-----\n");


	//char certificate_prefix2[BUF_SIZE] = "-----BEGIN CERTIFICATE-----\n";
	char certificate_postfix2[30] = "-----END CERTIFICATE-----\n";
	char txt_record_signature[BUF_SIZE];
	char newline[4] = "\n";
	char * ztls_version = "v=pqztls_1";
	char *ztls_cert_copy;
	ztls_cert_copy = (char *) malloc(sizeof(char)*7000);
	//printf("ztls_cert2: \n%s\n\n", ztls_cert);
	int k=0;
	for (int i = 0; *(ztls_cert+i)!='\0'; ++i)
	{
		if(*(ztls_cert+i)!='\n'){
			ztls_cert_copy[k++] = *(ztls_cert+i);
		}
	}
	ztls_cert_copy[k]='\0';

	//printf("str :\n%s\n", str);
	//printf("ztls_cert_copy: \n%s\n\n", ztls_cert_copy);
	//v=ztls1 check
	//printf("txt records:\n %s\n", dnsmsg);
	tmp = strtok(dnsmsg," ");
	//printf("version: %s\n", tmp);
	strcat(truncated_dnsmsg_out,tmp);
	//strtok(NULL, " ");//" "
	if(0!=strcmp(tmp,ztls_version)){
		printf("DNS TXT record's ZTLS version error\n");
	}
    
	// load dns cache info
	tmp = strtok(NULL," ");
	//printf("cache: %s\n", tmp);
	strcat(truncated_dnsmsg_out,tmp);
    dp->DNSCacheInfo.validity_period_not_before = is_datetime(tmp);
	//printf("DNS cache period: %s~", tmp);
	//strtok(NULL," ");
	tmp = strtok(NULL," ");
	strcat(truncated_dnsmsg_out,tmp);
    dp->DNSCacheInfo.validity_period_not_after = is_datetime(tmp);
	//printf("%s\n", tmp);
	//strtok(NULL," ");
	tmp = strtok(NULL," ");
	//printf("max_early_data_size: %s\n", tmp);
	strcat(truncated_dnsmsg_out,tmp);
	dp->DNSCacheInfo.max_early_data_size = strtoul(tmp, NULL, 0);
	//strtok(NULL," ");
	tmp = strtok(NULL," ");
	//printf("id: %s\n", tmp);
	strcat(truncated_dnsmsg_out,tmp);
    dp->DNSCacheInfo.dns_cache_id  = strtoul(tmp, NULL, 0);
	//strtok(NULL," ");

	// load keyshare entry
	tmp = strtok(NULL," ");
	//printf("key num: %s\n", tmp);
	strcat(truncated_dnsmsg_out,tmp);
    dp->KeyShareEntry.group = strtoul(tmp, NULL, 10);
	//printf("dp->KeyshareEntry.group: %d\n",dp->KeyShareEntry.group);	
	tmp = strtok(NULL," ");
	int skey_dlen = atoi(tmp);
	printf("skey_dlen: %d\n", skey_dlen);
	//tmp = strtok(NULL," ");
	char token_buf[500];
	char *token;
	tmp = strtok(NULL," ");
	if (token != NULL) {
        	strncpy(tmp, token, sizeof(tmp) - 1);
    	}
	for (int i = 0; i < skey_dlen; i++)
	{
		token = strtok(NULL, " ");
		if (token != NULL) {
            // copy txt record chunks if token is not NULL
            		strncpy(token_buf, token, sizeof(token_buf) - 1);
            		token_buf[sizeof(token_buf) - 1] = '\0';
            		strncat(tmp, token_buf, sizeof(tmp) - strlen(tmp) - 1);

            	//	printf("tmp #%d %s\n", i, tmp);
		}	
		//strcat(tmp,strtok(NULL," "));
		//printf("tmp #%d %s\n",i, tmp);
	}
	//printf("publickey: %s\n\n", tmp);
	strcat(truncated_dnsmsg_out,tmp);
	//strcat(publickey_prefix, tmp);
	// load publickey
	for(int j = 0; j < 1103 ; j=j+64){
		strncat(publickey_prefix,tmp+j,64);
		strcat(publickey_prefix,"\n");
		//printf("hex_out_cert: %s", hex_out_cert);
	}

	//strcat(publickey_prefix,"\n");
	//strcat(publickey_prefix,tmp);
	strcat(publickey_prefix, publickey_postfix);
        //printf("publickey_prefix: %s\n",publickey_prefix);
	bio_key = BIO_new(BIO_s_mem());
 	printf("public key length: %d\n", BIO_puts(bio_key, publickey_prefix));


	PEM_read_bio_PUBKEY(bio_key, &(dp->KeyShareEntry.skey), NULL, NULL);

	ERR_print_errors_fp(stderr);
	if(dp->KeyShareEntry.skey == NULL){
		printf("pem read bio pubkey err\n");
	}
	free(publickey_prefix);

	// load certificate
	char * begin_cert = "B_CERTIFICATE";
	char * end_cert = "E_CERTIFICATE";
	strcat(truncated_dnsmsg_out,begin_cert);
	strcat(truncated_dnsmsg_out,ztls_cert_copy);

	free(ztls_cert_copy);
	
	strcat(truncated_dnsmsg_out,end_cert);
	//printf("truncated_dnsmsg_out: %s\n\n", truncated_dnsmsg_out);
	strcat(certificate_prefix2, ztls_cert);
	strcat(certificate_prefix2, certificate_postfix2);
	//printf("certificate_prefix2: %s\n\n", certificate_prefix2);

    bio_cert = BIO_new(BIO_s_mem());
    printf("cert length: %d\n", BIO_puts(bio_cert, certificate_prefix2));
	
    BIO_puts(bio_cert, certificate_prefix2);

    PEM_read_bio_X509(bio_cert, &(dp->cert), NULL, NULL);

    if(dp->cert == NULL){
		printf("pem read bio cert err\n");
	}

    free(certificate_prefix2);

// Client Certificate Request Check
// for demo No Client Certificate Request
	//strtok(NULL," ");
	tmp = strtok(NULL," ");
	strcat(truncated_dnsmsg_out,tmp);
	printf("Client Certificate Request: %s\n", tmp);
	
	//strtok(NULL," ");
	tmp = strtok(NULL," ");
	//printf("%s\n", tmp);
	strcat(truncated_dnsmsg_out,tmp);
	//printf("truncated_dnsmsg_out: %s\n\n", truncated_dnsmsg_out);
	
    
//	load TXT signature (cert verify)
	printf("signature_algorithms: %s\n", tmp);
    dp->CertVerifyEntry.signature_algorithms = strtoul(tmp, NULL, 0);
	//strtok(NULL," ");
	tmp = strtok(NULL," ");
    
    int i =0;

	while(i < 100){
		strcat(txt_record_signature, tmp);//value (1)
		tmp = strtok(NULL," ");
		if(tmp == NULL) break;
		
		//strcat(txt_record_signature, newline);
		//printf("fullsignature:%s\n", tmp);
		
		strcat(txt_record_signature, tmp);//value (2)
		tmp = strtok(NULL," ");
		if(tmp == NULL) break;
		//strcat(txt_record_signature, newline);
		
		strcat(txt_record_signature, tmp);//value (3)
		strtok(NULL," ");
		tmp = strtok(NULL," ");
		if(tmp == NULL) break;
		//strcat(txt_record_signature, newline);
		
		i++;
	}

	if (100 <= i ) {
		printf("SIGNATURE ERROR\n"); 
	}

	strcpy((char*)dp->CertVerifyEntry.cert_verify, txt_record_signature);
	//printf("cert_verify:\n%s\n",dp->CertVerifyEntry.cert_verify);
	    return 0;
}

static SSL_CTX *create_context(){
    SSL_CTX* ctx = SSL_CTX_new(SSLv23_client_method());
    if(!ctx) error_handling("fail to create ssl context");
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    return ctx;
}
/*
 * verify
 * set version
 */
static void keylog_callback(const SSL* ssl, const char *line){
    //printf("==============================================\n");
    //printf("%s\n", line);
}
static size_t resolve_hostname(const char *host, const char *port, struct sockaddr_storage *addr){
    struct addrinfo hint;
	memset(&hint, 0, sizeof(struct addrinfo));
	hint.ai_family = AF_INET;
	hint.ai_socktype = SOCK_STREAM;
    hint.ai_protocol = IPPROTO_TCP;
	struct addrinfo *res = 0;
    if(getaddrinfo(host, port, &hint, &res) != 0)
        error_handling("fail to transform address");
    size_t len = res->ai_addrlen;
    memcpy(addr, res->ai_addr, len);
    freeaddrinfo(res);
    return len;
}
static void configure_connection(SSL *ssl){
    SSL_set_tlsext_host_name(ssl, "ns1.esplab.io");
    SSL_set_connect_state(ssl);
    if(SSL_do_handshake(ssl) <= 0){
        ERR_print_errors_fp(stderr);
        error_handling("fail to do handshake");
    }
}
static void error_handling(char *message){
    fputs(message, stderr);
    fputc('\n', stderr);
    exit(1);
}

static int dns_info_add_cb(SSL *s, unsigned int ext_type,
                            unsigned int context,
                            const unsigned char **out,
                            size_t *outlen, X509 *x, size_t chainidx,
                            int *al, void *arg)
                            {

    if (context == SSL_EXT_CLIENT_HELLO) {
        *out = (unsigned char*)malloc(sizeof(char*)*4);
        memcpy((void*)*out, &(&dns_info)->DNSCacheInfo.dns_cache_id, 4);
        *outlen = 4;
    }

    return 1;
}

static void dns_info_free_cb(SSL *s, unsigned int ext_type,
                     unsigned int context,
                     const unsigned char *out,
                     void *add_arg){
    OPENSSL_free((unsigned char *)out);
}

static int ext_parse_cb(SSL *s, unsigned int ext_type,
                        const unsigned char *in,
                        size_t inlen, int *al, void *parse_arg)
                        {
    return 1;
}

static time_t is_datetime(const char *datetime){
    // datetime format is YYYYMMDDHHMMSSz
    struct tm   time_val;

    strptime(datetime, "%Y%m%d%H%M%Sz", &time_val);

    return mktime(&time_val);       // Invalid
}


unsigned char *hex_to_base64(unsigned char **hex_data, int* size, unsigned char hex[], int tlsa_num)
{
	//printf("hex_to_base64 start: %d\n",size_1);
	int dilithium2_crt_len = 0;
	char temp[10];
	unsigned char * temc[tlsa_num];
	unsigned char n;
    size_t input_len = 0;
	for (int i = 0; i < tlsa_num; ++i)
	{
		temc[i]=*(hex_data+i);
		for(int j=0; j<*(size+i) ; j++) {
			sprintf(temp,"%02X",*(temc[i]) );
			strcat(hex,temp);
			temc[i]++;
		}
		input_len += *(size+i);
	}
/*
	for(int i=0; i<size_2 ; i++) {
		sprintf(temp,"%02X",*temc2 );
		strcat(hex,temp);
		temc2++;
	}*/
	unsigned char *hex_string = hex;

    static const char base64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";


    //printf("size_1:%d\n, size_2:%d\n", size_1,size_2);
    size_t output_len = 5500;
    char * out_buf = malloc(output_len);
    if (!out_buf) {
        return out_buf;
    }

    unsigned int digits;
    int d_len;
    int a=0;
    char *out = out_buf;
    while (*hex_string) {
    	
        if (sscanf(hex_string, "%3x%n", &digits, &d_len) != 1) {
            /* parse error */
            free(out_buf);
            return NULL;
        }
        
        switch (d_len) {
        case 3:
            *out++ = base64[digits >> 6];
            dilithium2_crt_len ++;
            *out++ = base64[digits & 0x3f];
            dilithium2_crt_len ++;
            break;
        case 2:
            digits <<= 4;
            *out++ = base64[digits >> 6];
            dilithium2_crt_len ++;
            *out++ = base64[digits & 0x3f];
            dilithium2_crt_len ++;
           
            *out++ = '=';
            dilithium2_crt_len ++;
            *out++ = '=';
            dilithium2_crt_len ++;
            break;
        case 1:
        	digits <<= 2;
            *out++ = base64[digits];
            dilithium2_crt_len ++;
            *out++ = '=';
            dilithium2_crt_len ++;
            //*out++ = '=';
            
        }
        hex_string += d_len;
        
    }

    *out++ = '\0';
    //printf("dilithium2_crt_len: %d\n", dilithium2_crt_len);
   
   

    return out_buf;
}
