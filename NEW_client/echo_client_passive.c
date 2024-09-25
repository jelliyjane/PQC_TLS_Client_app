#include "new_echo_client.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <arpa/nameser.h>
#include <netinet/in.h>
#include <resolv.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <netdb.h>

FILE *fp;

#define BUF_SIZE 60000
#define TXT_NUM 1
#define TLSA_NUM 1
//#define MAX(a, b) ((a) > (b) ? (a) : (b))
//#define MIN(a, b) ((a) < (b) ? (a) : (b))

#if MODE
int DNS = 1;
#else
int DNS = 0;
#endif
// 0 = false; //normal TLS 1.3 
// 1 = true;  //ZTLS  
pthread_mutex_t mutex;

static int start_time_idx = -1;
static int my_idx = -1;

typedef struct
{
    double handshake_start;
    double handshake_end;
    double cert_received;
    double send_client_hello;

} DeliveryTime;

double aquerytime = 0;
double txtquerytime = 0;
double tlsaquerytime = 0;
double totalquerytime = 0; 
double txt_before = 0;
double txt_after = 0;
double tlsa_before = 0;
double tlsa_after = 0;
double a_before = 0;


unsigned char* base64_decode(const char* b64message, size_t* out_len) {
    BIO *bio, *b64;
    int decode_len = strlen(b64message);
    unsigned char* buffer = (unsigned char*)malloc(decode_len);
    
    bio = BIO_new_mem_buf(b64message, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);  // 줄바꿈 없는 Base64 처리
    
    *out_len = BIO_read(bio, buffer, decode_len);
    
    BIO_free_all(bio);
    
    return buffer;
}

void info_callback(const SSL *ssl, int where, int ret)
{
    OSSL_HANDSHAKE_STATE state = SSL_get_state(ssl);
    DeliveryTime *timing_data = (DeliveryTime *)SSL_get_ex_data(ssl, my_idx);

    struct timespec current_time;
    clock_gettime(CLOCK_MONOTONIC, &current_time);
    double now = current_time.tv_sec + (current_time.tv_nsec / 1000000000.0);

    if (where & SSL_CB_HANDSHAKE_START)
    {
    	if(!timing_data->handshake_start){
    	timing_data->handshake_start = now;
    	printf("\nPeriod1: SSL_CB_HANDSHAKE_START: %f\n", timing_data->handshake_start );
    	}
    }

    if (state == TLS_ST_CW_CLNT_HELLO)
    {
    	timing_data->send_client_hello = now;
    	printf("\nPeriod2: TLS_ST_CW_CLNT_HELLO: %f\n", timing_data->send_client_hello);
    }
    
    if (state == TLS_ST_CR_CERT_VRFY)
   {
    	timing_data->cert_received = now;
    	printf("\nPeriod3: TLS_ST_CR_CERT_VRFY: %f\n", timing_data->cert_received);
    }


    if (where & SSL_CB_HANDSHAKE_DONE)
    {
    	timing_data->handshake_end = now;
    	printf("\nPeriod4: SSL_CB_HANDSHAKE_DONE: %f\n", timing_data->handshake_end);
    }
}

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
        unsigned char *cert_verify; // signature
    } CertVerifyEntry;
} dns_info;

static void init_openssl();
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
static int txt_query_retry(char *argv[], int txt_num, unsigned char query_txt_buffer[], unsigned char *txt_record_data, int* pqtxt_record_len);
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
	int *pqtxt_record_len;
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

static void *thread_txt_query_retry(void* arguments)
{
	struct arg_struct3* args = (struct arg_struct3 *) arguments;
	txt_query_retry(args->argv, args->txt_num, args->txt_query_buffer , args->txt_record_data, args->pqtxt_record_len);
	pthread_exit(NULL);
}

void log_times(double aquerytime, double txtquerytime, double tlsaquerytime, double totalquerytime,
               double handshake_start, double send_client_hello, double cert_received, double handshake_end) {
    fprintf(fp, "%f,%f,%f,%f,%f,%f,%f,%f\n",
            aquerytime, txtquerytime, tlsaquerytime, totalquerytime,
            handshake_start, send_client_hello, cert_received, handshake_end);
}


double start_time;
double total_runtime;

static int ext_add_cb(SSL *s, unsigned int ext_type,
                      const unsigned char **out,
                      size_t *outlen, int *al, void *add_arg)
{
    switch (ext_type) {
        case 65280:
            printf("ext_add_cb from client called!\n");
            break;

        default:
            break;
    }
    return 1;
}

static void ext_free_cb(SSL *s, unsigned int ext_type,
                        const unsigned char *out, void *add_arg)
{
    printf("ext_free_cb from client called\n");

}
struct timespec point;

int main(int argc, char *argv[]){
		////////////////INIT BENCH////////////////

	fp = fopen("time_measurements.csv", "a+");
    if (fp == NULL) {
        printf("Error opening file!\n");
        return 1;
	}
	fseek(fp, 0, SEEK_END);
	long filesize = ftell(fp); 

	if (filesize == 0) {
        fprintf(fp, "DNS A Query Time,DNS TXT Query Time,DNS TLSA Query Time,DNS Total Query Time,SSL Handshake Start,Send Client Hello,Receive Certificate,SSL Handshake Finish\n");
    }
    fseek(fp, 0, SEEK_SET);

    ////////////////INIT BENCH////////////////

    clock_gettime(CLOCK_MONOTONIC, &point);
    double start_time = (point.tv_sec) + (point.tv_nsec) / 1000000000.0;
	res_init();
	init_openssl();
	SSL_CTX *ctx = create_context();
	// static ctx configurations 
	SSL_CTX_load_verify_locations(ctx, "../dns/new_cert/dil2_crt.pem", "./dns/new_cert/");
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL); // SSL_VERIFY_NONE
	SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
	SSL_CTX_set_keylog_callback(ctx, keylog_callback);
    SSL_CTX_set_info_callback(ctx, info_callback);
	SSL * ssl = NULL;

	DeliveryTime *timing_data = malloc(sizeof(DeliveryTime));
	memset(timing_data, 0, sizeof(DeliveryTime));
	my_idx = SSL_get_ex_new_index(0, "DeliveryTime index", NULL, NULL, NULL);

    int sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(sock < 0){
        error_handling("socket() error");
    }

    struct sockaddr_storage addr;

	char hex_buffer[60000];
	
	int PUBKEY_SIZE;
	int SIGN_SIZE;
	int SIGN_SIZE_BASE64;
	int CERT_LENGTH;

	if(DNS==0 && argc==3){
		printf("TLS 1.3 mode\n");
	/*	
	}else if(argc <= 3+tlsa_num && argc <= 3+txt_num){
        printf("Usage : %s <port>\n please check number arguments", argv[0]);
        exit(1);
     */
    }
    else if(DNS==1){

	    if(strcmp(argv[3],"dil2")==0){
	    	PUBKEY_SIZE = 1312;
	    	SIGN_SIZE_BASE64 = 3228;
	    	SIGN_SIZE = 2420;
	    	CERT_LENGTH = 5312;
	    }
	    else if(strcmp(argv[3],"dil3")==0){
	    	PUBKEY_SIZE = 1952;
	    	SIGN_SIZE_BASE64 = 4392;
	    	SIGN_SIZE = 3293;
	    }
	        else if(strcmp(argv[3],"fal512")==0){
	    	PUBKEY_SIZE = 666;
	    	SIGN_SIZE_BASE64 = 4392;
	    	int SIGN_SIZE = 3293;
	    }
	        else if(strcmp(argv[3],"fal1024")==0){
	    	PUBKEY_SIZE = 666;
	    	SIGN_SIZE_BASE64 = 4392;
	    	SIGN_SIZE = 3293;
	    }
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
    
	// get TXT record & dynamic ctx configurations for ExpressPQDelivery
    if(DNS){
    	_res.options = _res.options | RES_USE_EDNS0 ; 	// use EDNS0 

		unsigned char query_passive_buffer[3000];
		char * passive_record_data =(char*) malloc(sizeof(char)*3000);
		int txt_passive_len = 0;
		struct arg_struct3 txt_passive;
		txt_passive.argc = argc;
		txt_passive.argv = argv;
		txt_passive.txt_num = 1;
		txt_passive.txt_query_buffer = query_passive_buffer;
		txt_passive.txt_record_data = passive_record_data;
		txt_passive.pqtxt_record_len = &txt_passive_len;

		//txt_query_retry(txt_passive.argv, txt_passive.txt_num, txt_passive.txt_query_buffer , txt_passive.txt_record_data);
		pthread_t ptid_passive;
		pthread_create(&ptid_passive, NULL, &thread_txt_query_retry, (void *)(&txt_passive));
		pthread_join(ptid_passive, NULL);
		char passive_txt[sizeof(char)*5000];
		//strcpy(passive_txt,passive_record_data[0]);
		/*
		for (int i = 0; i < txt_passive_len; i++)
		{
			printf("%02x", passive_record_data[i]);
		}
		*/
		char tmp;
		memcpy(&tmp, passive_record_data+1, 1);
		int txt_num_total = atoi(&tmp);
		printf("txt_num_total: %d\n", txt_num_total);

		memcpy(&tmp, passive_record_data+3, 1);
		int tlsa_num_total = atoi(&tmp);
		printf("tlsa_num_total: %d\n", tlsa_num_total);

		//printf("txt:%d tlsa:%d\n",txt_num_total, tlsa_num_total);
		//printf("passive_txt: %s\n", passive_txt);

		int txt_num = txt_num_total;
		unsigned char query_txt_buffer[txt_num][2000];
		char** txt_record_data;
		txt_record_data = (char**) malloc(sizeof(char*) * txt_num);
		for (int i = 0; i < txt_num; ++i)
		{
			txt_record_data[i]=(char*) malloc(sizeof(char)*2000);
		}


		//pqtlsa
		int tlsa_num = tlsa_num_total;
		unsigned char **pqtlsa_record_all = (unsigned char **)malloc(tlsa_num * sizeof(unsigned char*));
		for (int i = 0; i < tlsa_num; i++) {
        	pqtlsa_record_all[i] = (unsigned char *)malloc(10000*sizeof(unsigned char*));

		}
		
		//unsigned char *pqtlsa_record_all[tlsa_num];
		char pqtlsa_record[BUF_SIZE];
		unsigned char query_pqtlsa_buffer[tlsa_num][3000];
		int pqtlsa_len[tlsa_num];

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
		int* pqtxt_record_len = (int*) malloc(sizeof(int)*txt_num);
		
		for (int i = 1; i < txt_num; i++)
		{
			args3[i].argc = argc;
			args3[i].argv = argv;
			args3[i].txt_num = i+1;
			args3[i].txt_query_buffer = query_txt_buffer[i];
			args3[i].txt_record_data = txt_record_data[i];
			args3[i].pqtxt_record_len = pqtxt_record_len+i;
		}
		//args3[0].txt_record_data = passive_txt;

		//free(passive_record_data);

		pthread_t ptid_pqtlsa[tlsa_num];

		pthread_mutex_init(&mutex,NULL);
		for (int i = 0; i < tlsa_num; ++i)
		{
			pthread_create(ptid_pqtlsa+i, NULL, &thread_tlsa_query, (void *)(args2+i));
		}
		// A thread is created when a program is executed, and is executed when a user triggers
		//sleep(1);
		is_start = 1;
		pthread_t ptid_txt[txt_num];
		for (int i = 1; i < txt_num; ++i)
		{
			pthread_create(ptid_txt+i, NULL, &thread_txt_query_retry, (void *)(args3+i));
		}


	    for (int i = 0; i < tlsa_num; ++i)
	    {
	    	pthread_join(ptid_pqtlsa[i], (void **)(pqtlsa_len+i));
	    }

		
		for (int i = 1; i < txt_num; ++i)
	    {
		    pthread_join(ptid_txt[i], NULL);
	    }

	    //pthread_join(ptid_txt[0], NULL);

	pthread_join(ptid, NULL);
	pthread_mutex_destroy(&mutex);

	//-------------------TLSA(server's certificate) BASE64 Encoding--------------------
	unsigned char * based64_out;
	based64_out = hex_to_base64(pqtlsa_record_all, pqtlsa_len,  hex_buffer, tlsa_num);
	//based64_out = hex_to_base64(tlsa2_record_all, tlsa2_len, hex_buffer);
	char newline2[4] = "\n";
	char* ztls_cert;
    ztls_cert = (char*) malloc(sizeof(char)*10000);
	//for(int j = 0; j < 916-64 ; j=j+64){ 908
	for(int j = 0; j < CERT_LENGTH ; j=j+64){
		strncat(ztls_cert,based64_out+j,64);
		strcat(ztls_cert,newline2);
		//printf("hex_out_cert: %s", hex_out_cert);
	}
	//printf("ztls_cert: \n%s\n", ztls_cert);

	//-------------------------Certificate Hash-------------------------
	
	int merged_tlsa_length = 0;
	for (int i = 0; i < tlsa_num; i++)
	{
		merged_tlsa_length += pqtlsa_len[i];
		//printf("pqtlsa_len: %d\n", pqtlsa_len[i]);
	}
	printf("merged_tlsa_length: %d\n", merged_tlsa_length);
	
	unsigned char* merged_tlsa_data = (unsigned char*)calloc(merged_tlsa_length, sizeof(unsigned char));
	int temp = 0;
	for (int i = 0; i < tlsa_num; i++)
	{
		memcpy(merged_tlsa_data+temp, pqtlsa_record_all[i], pqtlsa_len[i]);
		temp += pqtlsa_len[i];
	}
	/*
	for (int i = 0; i < merged_tlsa_length; i++)
	{
		printf("%02x", merged_tlsa_data[i]);
	}
	printf("\n\n");
	*/
	unsigned char* tlsa_hash = (unsigned char*)calloc(EVP_MAX_MD_SIZE, sizeof(unsigned char)); //sha256 digest size = 32 bytes
	char tlsa_hash_string[2 * EVP_MD_size(EVP_sha256()) + 1];  // 2 characters per byte + null terminator
    EVP_MD_CTX *mdctx;
    unsigned int tlsa_hash_length;

	mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        printf("EVP_MD_CTX_new error\n");
        free(tlsa_hash);
        return -1;
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        printf("SHA-256 initialization failed\n");
        EVP_MD_CTX_free(mdctx);
        free(tlsa_hash);
        return -1;
    }

     if (EVP_DigestUpdate(mdctx, merged_tlsa_data, merged_tlsa_length) != 1) {
        printf("SHA-256 update failed\n");
        EVP_MD_CTX_free(mdctx);
        free(tlsa_hash);
        return -1;
    }

    if (EVP_DigestFinal_ex(mdctx, tlsa_hash, &tlsa_hash_length) != 1) {
        printf("SHA-256 finalization failed\n");
        EVP_MD_CTX_free(mdctx);
        free(tlsa_hash);
        return -1;
    }

    for (unsigned int i = 0; i < tlsa_hash_length; i++) {
        sprintf(&tlsa_hash_string[i * 2], "%02x", tlsa_hash[i]);
    }
    tlsa_hash_string[2 * tlsa_hash_length] = '\0';

    //printf("SHA-256 hash: %s\n", tlsa_hash_string);

    EVP_MD_CTX_free(mdctx);
    free(tlsa_hash);



    /*for (int i = 0; i < tlsa_num; i++) {
    	free(pqtlsa_record_all[i]);
    }
    free(pqtlsa_record_all);
	*/

	//********************************************************
	//*********************Generate E-Box*********************
	char *txt_record_all = (char*) malloc(sizeof(char)*10000);
	memcpy(txt_record_all, passive_record_data, txt_passive_len);

	int	txt_record_all_len = txt_passive_len;
	for (int i = 1; i<txt_num; i++){
		//printf("%d\n", pqtxt_record_len[i]);
		memcpy(txt_record_all+txt_record_all_len,txt_record_data[i],pqtxt_record_len[i]);
		txt_record_all_len += pqtxt_record_len[i];
	}
	free(passive_record_data);
	
	/*printf("txt_record_all:");
	for (int i = 0; i < txt_record_all_len; i++)
	{
		printf("%02x", txt_record_all[i]);
	}
	printf("\n");*/
	
	
	for (int i = 1; i < txt_num; ++i)
	{
		free(txt_record_data[i]);
	}
	free(txt_record_data);
	//printf("txt_record_all:\n%s\n\n",txt_record_all);
	
	//---------------------Total TXT and TLSA records---------------------
	char* ebox_val = (char*)calloc(97,sizeof(char));
	char txt_record_except_signature[BUF_SIZE]="";
	
	int offset = 0;
	char a = txt_num + '0';
	strcat(ebox_val, &a);
	
	offset += 3;
	//printf("%02x\n", txt_record_all[offset]);

	a = tlsa_num + '0';
	strcat(ebox_val, &a);
	offset += 2;
	//printf("%02x\n", *(txt_record_all+offset));

	//---------------------ExpressPQDelivery version---------------------
	int ExpressPQDelivery_v = 0;
	memcpy(&ExpressPQDelivery_v, txt_record_all+offset, 1);
	offset += 2;
	a = (char) ExpressPQDelivery_v;
	strcat(ebox_val, &ExpressPQDelivery_v);
	//printf("ExpressPQDelivery_v: %02x\n\n", ExpressPQDelivery_v);

	char protocol;
	memcpy(&protocol, txt_record_all+offset, 1);
	offset += 2;
	a = (char) protocol;
	strcat(ebox_val, &protocol);

	//printf("protocol: %c\n\n", protocol);

	//---------------------E-Box validity period---------------------
	unsigned char* day_before = (unsigned char*)malloc(sizeof(unsigned char)*14);
	unsigned char* day_after = (unsigned char*)malloc(sizeof(unsigned char)*14);

	memcpy(day_before, txt_record_all+offset, 14);
	offset += 15;
	strcat(ebox_val, day_before);

	memcpy(day_after, txt_record_all+offset, 14);
	offset += 15;
	strcat(ebox_val, day_after);
	/*
	for (int i = 0; i < 14; ++i)
	{
		printf("%c", day_after[i]);
	}
	printf("\n");
	*/
	dns_info.DNSCacheInfo.validity_period_not_before = is_datetime(day_before);
	dns_info.DNSCacheInfo.validity_period_not_after = is_datetime(day_after);

	time_t current_time = time(NULL);  
    struct tm *local_time = localtime(&current_time); 

    printf("current time: %d-%02d-%02d %02d:%02d:%02d\n",
           local_time->tm_year + 1900,
           local_time->tm_mon + 1,      
           local_time->tm_mday,         
           local_time->tm_hour,         
           local_time->tm_min,          
           local_time->tm_sec);   

	//printf("%d\n", (dns_info.DNSCacheInfo.validity_period_not_before < time(NULL)));
	//printf("%d\n", (dns_info.DNSCacheInfo.validity_period_not_after > time(NULL)));

	if((dns_info.DNSCacheInfo.validity_period_not_before < time(NULL)) && (dns_info.DNSCacheInfo.validity_period_not_after > time(NULL))){
    	printf("Valid Period\n");
	}else{
   	 	printf("Not Valid Period\n");
	}
	free(day_before);
	free(day_after);
	
	//---------------------E-Box signature algorithm---------------------
	char ebox_sig_name;
	memcpy(&ebox_sig_name, txt_record_all+offset, 1);
	offset += 2;
	strcat(ebox_val, &ebox_sig_name);

	if(ebox_sig_name == '0'){	
		dns_info.CertVerifyEntry.signature_algorithms = 0xfea0; 	//dilithium2
	}
	if(ebox_sig_name == '1'){
		dns_info.CertVerifyEntry.signature_algorithms = 0xfea3;		//dilithium3
	}
	if(ebox_sig_name == '2'){
		dns_info.CertVerifyEntry.signature_algorithms = 0xfea5;		//dilithium5
	}
	if(ebox_sig_name == '3'){
		dns_info.CertVerifyEntry.signature_algorithms = 0xfed7;		//falcon512
	}
	if(ebox_sig_name == '4'){
		dns_info.CertVerifyEntry.signature_algorithms = 0xfeda;		//falcon1024
	}
	//printf("dns_info.CertVerifyEntry.signature_algorithms: %02x\n\n", dns_info.CertVerifyEntry.signature_algorithms);
	

	//---------------------Add certificate HASH---------------------
	memcpy(ebox_val+33, tlsa_hash_string, 64);

	printf("ebox-val: %s\n", ebox_val);

	//---------------------E-Box signature value--------------------
	//printf("txt_record_all[offset -1]: %02x\n",(unsigned char)txt_record_all[offset -1]);
	//printf("SIGN_SIZE_BASE64: %d\n", SIGN_SIZE_BASE64);
	int len = 0;
	int cur_len = 0;
	dns_info.CertVerifyEntry.cert_verify  = (unsigned char*) calloc(SIGN_SIZE_BASE64, sizeof(unsigned char));
	do{
		len = (unsigned char)txt_record_all[offset -1];
		//printf("len: %d\n", len);
		cur_len = cur_len + len;
		memcpy(dns_info.CertVerifyEntry.cert_verify + cur_len - len, txt_record_all+offset, len);
		offset += (len + 1);
		/*for (int i = cur_len - len; i < cur_len; ++i)
		{
			printf("%02x", dns_info.CertVerifyEntry.cert_verify[i]);
		}
		printf("\n\n");*/
	}while(offset < txt_record_all_len);
	dns_info.CertVerifyEntry.cert_verify[SIGN_SIZE_BASE64] = '\0';

	free(txt_record_all);
	/*for (int i = 0; i < 3228; i++)
	{
		printf("%02x", dns_info.CertVerifyEntry.cert_verify[i]);
	}
	printf("\n");*/
	//printf("%s\n\n", dns_info.CertVerifyEntry.cert_verify);

	//------------------------add pem config------------------------
	char* cert_prefix = (char*)calloc(10000, sizeof(char));
	strcat(cert_prefix, "-----BEGIN CERTIFICATE-----\n");
	strncat(cert_prefix, ztls_cert, strlen(ztls_cert));
	strcat(cert_prefix, "-----END CERTIFICATE-----");

	//printf("cert_prefix: %s\n", cert_prefix);
	BIO *bio_cert = BIO_new(BIO_s_mem());

    printf("cert length: %d\n", BIO_puts(bio_cert, cert_prefix));
    free(ztls_cert);
    //BIO_puts(bio_cert, certificate_prefix2);

    PEM_read_bio_X509(bio_cert, &(dns_info.cert), NULL, NULL);

	SSL_CTX_add_custom_ext(ctx, 53, SSL_EXT_CLIENT_HELLO, dns_info_add_cb, dns_info_free_cb,NULL, NULL,NULL);// extentionTye = 53, Extension_data = dns_cache_id

	if(dns_info.KeyShareEntry.group == 570){  // keyshare group : 570, kyber
		
		ssl = SSL_new(ctx);
        SSL_set_ex_data(ssl, my_idx, timing_data);
	if(!SSL_set1_groups_list(ssl, "kyber512"))
		error_handling("fail to set kyber512");
	}
	else{
	    dns_info.KeyShareEntry.group = 570;
	    int result_cb = SSL_CTX_add_client_custom_ext(ctx, 65280, ext_add_cb, ext_free_cb, NULL, ext_parse_cb, NULL);
	    ssl = SSL_new(ctx);
	    SSL_set_ex_data(ssl, my_idx, timing_data);
	    if (!SSL_set1_groups_list(ssl, "kyber512"))
	        error_handling("fail to set kyber512");
	}
	

	//ssl = SSL_new(ctx);
	SSL_set_wfd(ssl, DNS); // fd : 1 => ZTLS, fd : 0 => TLS 1.3
    //printf("return of ssl set wfd: %d\n", SSL_set_wfd(ssl, DNS));

	//printf("return of server public key: %d\n",SSL_use_PrivateKey(ssl, dns_info.KeyShareEntry.skey)); // set server's keyshare // this function is modified 
    EVP_PKEY *pubkey = X509_get_pubkey(dns_info.cert);
    if (!pubkey)
    {
        fprintf(stderr, "Failed to get public key from certificate\n");
        return -1;
    }

    int ret = X509_verify(dns_info.cert, pubkey);

    if (ret != 1)
    {
        fprintf(stderr, "Certificate verification failed\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    else{
    	printf("Certificate is valid\n");
    }

    BIO *bio_file = BIO_new(BIO_s_file());
    const char *cert_filename = "../dns/new_cert/dil2_crt.pem";
    BIO_read_filename(bio_file, cert_filename);  // 인증서 파일 경로
    dns_info.cert = PEM_read_bio_X509(bio_file, NULL, NULL, NULL);

	if (cert_filename == NULL) {
    	fprintf(stderr, "Failed to load certificate.\n");
    	exit(EXIT_FAILURE);
	}

	//********************************************************
	//-------------------E-Box Verification-------------------
    printf("return of ssl_use_certificate: %d\n", SSL_use_certificate(ssl, dns_info.cert)); // set sever's cert and verify cert_chain // this function is modified
	if((dns_info.CertVerifyEntry.signature_algorithms == 0xfea0) || 
		(dns_info.CertVerifyEntry.signature_algorithms == 0xfea3) || 
		(dns_info.CertVerifyEntry.signature_algorithms == 0xfea5) || 
		(dns_info.CertVerifyEntry.signature_algorithms == 0xfed7) || 
		(dns_info.CertVerifyEntry.signature_algorithms == 0xfeda))     //dil2
	{
		//printf("txt_record_except_signature\n");
		//printf("%s",txt_record_except_signature );
		
		//printf("\ndns_info.CertVerifyEntry.cert_verify\n");
		//printf("%s",dns_info.CertVerifyEntry.cert_verify );
		EVP_MD_CTX *mdctx = NULL;

	    mdctx = EVP_MD_CTX_new();
	    if (!mdctx)
	        return -1;

	    if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pubkey) <= 0)
	        printf("verify init failed\n");

	    //int binary_signature_len;
	    printf("strlen(dns_info.CertVerifyEntry.cert_verify): %d\n",strlen(dns_info.CertVerifyEntry.cert_verify));
	    printf("SIGN_SIZE_BASE64: %d\n", SIGN_SIZE_BASE64);
	    //unsigned char* binary_signature = (unsigned char*)malloc(sizeof(unsigned char)*SIGN_SIZE);
	    //base64_decode(dns_info.CertVerifyEntry.cert_verify, SIGN_SIZE_BASE64, binary_signature, &binary_signature_len);

	    //printf("\n");
	    unsigned char* base64_sign = (unsigned char*)malloc(sizeof(unsigned char)*SIGN_SIZE_BASE64);
	    size_t base64_sign_len = EVP_DecodeBlock(base64_sign, dns_info.CertVerifyEntry.cert_verify, SIGN_SIZE_BASE64);
	    base64_sign[SIGN_SIZE] = '\0';
	    /*
	    for (int i = 0; i < SIGN_SIZE_BASE64; ++i)
	    {
	    	printf("%02x", base64_sign[i]);
	    }
	    printf("\n\n");
	    printf("base64_sign_len: %d\n", base64_sign_len);
		*/

	    if (EVP_DigestVerifyUpdate(mdctx, ebox_val, 97) <= 0) {
	        fprintf(stderr, "EVP_DigestVerifyUpdate 실패\n");
	        ERR_print_errors_fp(stderr);
	        EVP_MD_CTX_free(mdctx);
        	return 0;
    	}

	    int result = EVP_DigestVerifyFinal(mdctx, base64_sign, SIGN_SIZE);
	    if (result == 1) {
	        printf("E-Box verification Success!\n");
	    } else if (result == 0) {
	        printf("E-Box verification failed:(\n");
	        return -1;
	    } else {
	        fprintf(stderr, "error!\n");
	        ERR_print_errors_fp(stderr);
	    }

	    // 컨텍스트 해제
	    EVP_MD_CTX_free(mdctx);
	    EVP_PKEY_free(pubkey);

		}

    }else {
		is_start = 1;

		init_tcp_sync(argc, argv, &addr, sock, &is_start);
    	ssl = SSL_new(ctx);
        SSL_set_ex_data(ssl, my_idx, timing_data);
    	if(!SSL_set1_groups_list(ssl, "kyber512"))
			error_handling("fail to set kyber512");
    	SSL_set_wfd(ssl, DNS); // fd : 1 => ZTLS, fd : 0 => TLS 1.3
	}
	// threads join

    SSL_set_fd(ssl, sock);
    /*
     * handshake start
     */
    configure_connection(ssl); // SSL do handshake
    struct timespec total;
    clock_gettime(CLOCK_MONOTONIC, &total);
    double execution_time = (total.tv_sec) + (total.tv_nsec) / 1000000000.0; //for bench
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
		clock_gettime(CLOCK_MONOTONIC, &total);
		execution_time = (total.tv_sec) + (total.tv_nsec) / 1000000000.0; //for bench
    }

    double total_runtime = execution_time - start_time;
    if(DNS)
	    total_runtime = total_runtime-1; //elemination sleeptime on code
    //fprintf(fp, "%f\n", total_runtime);
    txtquerytime = txt_after - txt_before;
    tlsaquerytime = tlsa_after - tlsa_before;
    totalquerytime = MAX(txt_after, tlsa_after) - MIN(txt_before, a_before);

    printf("total_runtime %f\n", total_runtime);
    printf("==========================result===========================\n");
    printf("\nDNS A query time: %f\n", aquerytime);
    printf("\nDNS TXT query time: %f\n", txtquerytime);
    printf("\nDNS TLSA query time: %f\n", tlsaquerytime);
    printf("\nDNS total query / response time: %f\n", totalquerytime);
    printf("\nPeriod1: SSL_CB_HANDSHAKE_START: %f\n", timing_data->handshake_start );
    printf("\nPeriod2: Send client hello: %f\n", timing_data->send_client_hello );
    printf("\nPeriod3: Recieve certificate: %f\n", timing_data->cert_received );
    printf("\nPeriod4: SSL_CB_HANDSHAKE_FINISH: %f\n", timing_data->handshake_end );

    log_times(aquerytime, txtquerytime, tlsaquerytime, totalquerytime, timing_data->handshake_start, timing_data->send_client_hello, timing_data->cert_received, timing_data->handshake_end);

    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    free(timing_data);
	fclose(fp);

    return 0;
}
static void init_tcp_sync(int argc, char *argv[], struct sockaddr_storage * addr, int sock, int * is_start) {
	while(*is_start < 0) { //for prototyping. next, use signal.
		//nothing
	}
    struct timespec begin1, begin2;
    clock_gettime(CLOCK_MONOTONIC, &begin1);
    printf("start A and AAAA DNS records query : %f\n",(begin1.tv_sec) + (begin1.tv_nsec) / 1000000000.0);
    a_before = (begin1.tv_sec) + (begin1.tv_nsec) / 1000000000.0;
    printf("%s, %s\n",argv[1],argv[2]);
    //size_t len = resolve_hostname(argv[1], argv[3], addr);
    size_t len = resolve_hostname(argv[1], argv[2], addr);
    clock_gettime(CLOCK_MONOTONIC, &begin2);
    printf("complete A and AAAA DNS records query : %f\n",(begin2.tv_sec) + (begin2.tv_nsec) / 1000000000.0);
    double ending = (begin2.tv_sec) + (begin2.tv_nsec) / 1000000000.0;
    aquerytime = ending - a_before;
	if(connect(sock, (struct sockaddr*) addr, len) < 0){
        error_handling("connect() error!");
    }else{
    	clock_gettime(CLOCK_MONOTONIC, &begin2);
    	printf("complete TCP Sync : %f\n",(begin2.tv_sec) + (begin2.tv_nsec) / 1000000000.0);
    }
}

static int dns_query_with_timeout(const char *domain, int type, unsigned char *answer) {
    struct __res_state res_state;
   // ns_type type;
	//type= ns_t_txt;

    if (res_ninit(&res_state) < 0) {
        printf("Failed to initialize resolver\n");
        return -1;
    }

    
    // 타임아웃 설정 (초 단위)
    res_state.retrans = 3;
    res_state.retry = 1;


    int response = res_nquery(&res_state, domain, C_IN, type, answer, 4096);

    res_nclose(&res_state);
    return response;
}

static int txt_query_retry(char *argv[], int txt_num, unsigned char query_txt_buffer[], unsigned char *txt_record_all, int* pqtxt_record_len) {
    int response = -1;
    ns_type type;
	type= ns_t_txt;
    ns_msg nsMsg;
	ns_rr rr;
	int retry_count = 2;
	char query_num[20];
	char query_url[25]="";
	char query_url_fix[20] = ".ebox-";
	char domain_name[20] = ".esplab.io";
	sprintf(query_num, "%d", txt_num-1);
	strcat(query_url,argv[3]);
	strcat(query_url,query_url_fix);
	strcat(query_url,query_num);
	strcat(query_url,domain_name);
    for (int i = 0; i < retry_count; ++i) {
        printf("Attempt %d to query TXT record for %s\n", i + 1, query_url);

        if(txt_before == 0)
        clock_gettime(CLOCK_MONOTONIC, &point);
		txt_before = (point.tv_sec) + (point.tv_nsec) / 1000000000.0;

        response =  res_search(query_url, C_IN, type, query_txt_buffer, 2000);

        clock_gettime(CLOCK_MONOTONIC, &point);
		txt_after = (point.tv_sec) + (point.tv_nsec) / 1000000000.0;

        if (response >= 0) {
        	//printf("response: %d\n", response);
            printf("Successfully received TXT response\n");
            ns_initparse(query_txt_buffer, response, &nsMsg);
	        if (ns_parserr(&nsMsg, ns_s_an, 0, &rr) < 0) {
	            fprintf(stderr, "Failed to parse answer section\n");
	            return -1;
	        }			
	        const u_char *rdata =  ns_rr_rdata(rr);
			int rdata_len = ns_rr_rdlen(rr);
			//printf("rdata_len: %d\n\n", rdata_len);
			memcpy(pqtxt_record_len, &rdata_len, 2);
			
			memcpy(txt_record_all, rdata, rdata_len);
			/*for (int i = 0; i < rdata_len; i++)
			{
				printf("%02x", txt_record_all[i]);
			}
			printf("\n\n");*/
			
			//printf("pqtxt_record_len: %d\n", *pqtxt_record_len);

		return 0;

        } else {
            printf("No response, retrying...\n");
        }
    }

    return -1;
}


static int 	tlsa_query(char *argv[], int tlsa_num, unsigned char query_buffer[], int buffer_size, unsigned char ** tlsa_record_all, int * is_start) {
	int retry_count = 2;
	while(*is_start < 0) { //for prototyping. next, use signal.
		//nothing
	}
	printf("pqtlsa_num: %d\n", tlsa_num-1);
	char query_num[20];
	char query_url[100] = "_443._udp.";
	char query_url_fix[20] = ".ebox-";
	char domain_name[20] = ".esplab.io";
	sprintf(query_num, "%d", tlsa_num-1);
	strcat(query_url,argv[3]);
	strcat(query_url,query_url_fix);
	strcat(query_url,query_num);
	strcat(query_url,domain_name);
//	printf("query_url in tlsa query: %s\n", query_url);

	//char query_url[100] = "_443._udp.";
	//strcat(query_url,argv[tlsa_num+2]);  //dilithium2
	ns_type type2;
	type2 = ns_t_tlsa;
	ns_msg nsMsg;
	ns_rr rr;
	int response;
	int len;
	
	struct timespec begin;
	clock_gettime(CLOCK_MONOTONIC, &begin);
	printf("start DNS PQTLSA query: %f\n",(begin.tv_sec) + (begin.tv_nsec) / 1000000000.0);
	//printf("start DNS TLSA query:\n");
	for (int i = 0; i < retry_count; ++i) {
    printf("Attempt %d to query TLSA record for %s\n", i + 1, query_url);

    if(tlsa_before == 0)
    clock_gettime(CLOCK_MONOTONIC, &begin);
	tlsa_before = (begin.tv_sec) + (begin.tv_nsec) / 1000000000.0;

    response = dns_query_with_timeout(query_url, type2, query_buffer);

    clock_gettime(CLOCK_MONOTONIC, &begin);
	tlsa_after = (begin.tv_sec) + (begin.tv_nsec) / 1000000000.0;

    if (response >= 0) {
    	printf("Successfully received TLSA response\n");
    	clock_gettime(CLOCK_MONOTONIC, &begin);
		printf("complete DNS PQTLSA query : %f\n",(begin.tv_sec) + (begin.tv_nsec) / 1000000000.0);
    	ns_initparse(query_buffer, response, &nsMsg);
		ns_parserr(&nsMsg, ns_s_an, 0, &rr);
		u_char const *rdata = (u_char*)(ns_rr_rdata(rr)+3);
		
		*tlsa_record_all = (unsigned char*)rdata;
		len = ns_rr_rdlen(rr);
	return len-3;
	}else {
        printf("No response, retrying...\n");
	}
	}

		//response = res_search(query_url, C_IN, type2, query_buffer, buffer_size);
		// log
    	clock_gettime(CLOCK_MONOTONIC, &begin);
    	printf("complete DNS PQTLSA query : %f\n",(begin.tv_sec) + (begin.tv_nsec) / 1000000000.0);
		//printf("complete DNS TLSA query :\n");
    /*
	if (response < 0) {
		printf("Error looking up service: TLSA \n");
	}
	ns_initparse(query_buffer, response, &nsMsg);
	ns_parserr(&nsMsg, ns_s_an, 0, &rr);
	u_char const *rdata = (u_char*)(ns_rr_rdata(rr)+3);
	
	*tlsa_record_all = (unsigned char*)rdata;

	int len = ns_rr_rdlen(rr);
	*/
    	
	return len-3;
}
static void init_openssl(){
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
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
    size_t output_len = 200000;
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
