#include "new_echo_client.h"

#include <arpa/nameser.h>
#include <netinet/in.h>
#include <resolv.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <netdb.h>

FILE *fp;

#define BUF_SIZE 10000
#define TLSA_NUM 8
#define TXT_NUM 8

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

int verify_self_signed_cert(X509 *cert)
{
    EVP_PKEY *pubkey = X509_get_pubkey(cert);
    if (!pubkey)
    {
        fprintf(stderr, "Failed to get public key from certificate\n");
        return -1;
    }

    int ret = X509_verify(cert, pubkey);
    EVP_PKEY_free(pubkey);

    if (ret != 1)
    {
        fprintf(stderr, "Certificate verification failed\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    printf("Certificate is valid\n");
    BIO *bio2 = BIO_new(BIO_s_file());

    if (bio2)
    {
        BIO_set_fp(bio2, stdout, BIO_NOCLOSE);


        if (!PEM_write_bio_PUBKEY(bio2, pubkey))
        {
            fprintf(stderr, "Error writing public key to standard output\n");
        }

        BIO_free(bio2);
    }

    return 0;
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


struct DNS_info
{
    struct
    {
        time_t validity_period_not_before; // gmt unix time
        time_t validity_period_not_after;  // gmt unix time
        uint32_t dns_cache_id;
        uint32_t max_early_data_size;
    } DNSCacheInfo;
    struct
    {
        uint8_t *extension_type;
        uint16_t *extension_data;
    } EncryptedExtensions;
    struct
    {
        uint16_t group;
        EVP_PKEY *skey; // server's keyshare
    } KeyShareEntry;
    X509 *cert; // server's cert
    struct
    {
        uint8_t certificate_request_context;
        uint16_t extensions;
    } CertRequest;
    struct
    {
        uint16_t signature_algorithms;
        unsigned char cert_verify[BUF_SIZE]; // signature
    } CertVerifyEntry;
} dns_info;

static void init_openssl();
static int load_dns_info2(struct DNS_info *dp, char *truncated_dnsmsg_out, char *dnsmsg, char *ztls_cert);
static SSL_CTX *create_context();
static void keylog_callback(const SSL *ssl, const char *line);
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

static void init_tcp_sync(int argc, char *argv[], struct sockaddr_storage *addr, int sock, int *is_start);
static int tlsa_query(char *argv[], int tlsa_num, unsigned char pqtlsa_query_buffer[], int buffer_size, unsigned char **tlsa_record_all, int *is_start);
static int tlsa_query_retry(char *argv[], int tlsa_num, unsigned char pqtlsa_query_buffer[], int buffer_size, unsigned char **tlsa_record_all, int *is_start);
static int txt_query(char *argv[], int txt_num, int **total_txt_num, unsigned char txt_query_buffer[], unsigned char *txt_record_data);
static int txt_query_retry(char *argv[], int txt_num, int **total_txt_num, unsigned char query_txt_buffer[], unsigned char *txt_record_data);
unsigned char *hex_to_base64(unsigned char **hex_data, int *size, unsigned char hex[], int tlsa_num);

struct arg_struct
{
    int argc;
    char **argv;
    struct sockaddr_storage *addr;
    int sock;
    int *is_start;
};
struct arg_struct2
{
    int argc;
    char **argv;
    int pqtlsa_num;
    unsigned char *pqtlsa_query_buffer;
    int buffer_size;
    int *pqtlsa_record_len;
    unsigned char **pqtlsa_record_all;
    int *is_start;
};
struct arg_struct3
{
    int argc;
    char **argv;
    int txt_num;
    int **total_txt_num;
    unsigned char *txt_query_buffer;
    unsigned char *txt_record_data;
};

static void *thread_init_tcp_sync(void *arguments)
{
    struct arg_struct *args = (struct arg_struct *)arguments;
    init_tcp_sync(args->argc, args->argv, args->addr, args->sock, args->is_start);
    pthread_exit(NULL);
}

static void *thread_tlsa_query(void *arguments)
{
    struct arg_struct2 *args = (struct arg_struct2 *)arguments;
    int tlsa_len = tlsa_query(args->argv, args->pqtlsa_num, args->pqtlsa_query_buffer, args->buffer_size, args->pqtlsa_record_all, args->is_start);

    return (void *)tlsa_len;
}

static void *thread_tlsa_query_retry(void *arguments)
{
    struct arg_struct2 *args = (struct arg_struct2 *)arguments;
    int tlsa_len = tlsa_query_retry(args->argv, args->pqtlsa_num, args->pqtlsa_query_buffer, args->buffer_size, args->pqtlsa_record_all, args->is_start);

    return (void *)tlsa_len;
}

static void *thread_txt_query(void *arguments)
{
    struct arg_struct3 *args = (struct arg_struct3 *)arguments;
    txt_query(args->argv, args->txt_num, args->total_txt_num, args->txt_query_buffer, args->txt_record_data);
    pthread_exit(NULL);
}

static void *thread_txt_query_retry(void *arguments)
{
    struct arg_struct3 *args = (struct arg_struct3 *)arguments;
    txt_query_retry(args->argv, args->txt_num, args->total_txt_num, args->txt_query_buffer, args->txt_record_data);
    pthread_exit(NULL);
}
void log_times(double aquerytime, double txtquerytime, double tlsaquerytime, double totalquerytime,
               double handshake_start, double send_client_hello, double cert_received, double handshake_end) {
    fprintf(fp, "%f,%f,%f,%f,%f,%f,%f,%f\n",
            aquerytime, txtquerytime, tlsaquerytime, totalquerytime,
            handshake_start, send_client_hello, cert_received, handshake_end);
}

struct timespec point;

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
    struct timespec total;
    clock_gettime(CLOCK_MONOTONIC, &total);
    double start_time = (total.tv_sec) + (total.tv_nsec) / 1000000000.0;
    res_init();
    init_openssl();
    my_idx = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    start_time_idx = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    SSL_CTX *ctx = create_context();
    // static ctx configurations
    SSL_CTX_load_verify_locations(ctx, "../dns/cert/dilithium2_crt.pem", "./dns/cert/");
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL); // SSL_VERIFY_NONE
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_keylog_callback(ctx, keylog_callback);
    SSL_CTX_set_info_callback(ctx, info_callback);
    SSL *ssl = NULL;

    DeliveryTime *timing_data = malloc(sizeof(DeliveryTime));
    memset(timing_data, 0, sizeof(DeliveryTime));

    int sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0)
    {
        error_handling("socket() error");
    }

    struct sockaddr_storage addr;

    char hex_buffer[7000];

    if (DNS == 0 && argc == 3)
    {
        printf("TLS 1.3 mode\n");
        /*
        }else if(argc <= 3+tlsa_num && argc <= 3+txt_num){
            printf("Usage : %s <port>\n please check number arguments", argv[0]);
            exit(1);
         */
    }
    int is_start = -1;
    int tlsa_num = TLSA_NUM;
    int txt_num = TXT_NUM;

    // log
    printf("****start****\n");
    if (!DNS)
    {
        struct timespec begin;
        clock_gettime(CLOCK_MONOTONIC, &begin);
        printf("start : %f\n", (begin.tv_sec) + (begin.tv_nsec) / 1000000000.0);
    }
    //=============================================================
    // Dynamic interaction start
    //=============================================================

    // get TXT record & dynamic ctx configurations for ZTLS
    if (DNS)
    {
        struct timespec begin;
        _res.options = _res.options | RES_USE_EDNS0; // use EDNS0
        unsigned char query_txt_buffer[txt_num][5000];
        char **txt_record_data;
        char *txt_record_all;
        char *txt_record_all_aid;
        unsigned char **pqtlsa_record_all_aid = NULL;
        txt_record_all = (char *)calloc(60000, sizeof(char));
        txt_record_all_aid = (char *)calloc(60000, sizeof(char));
        txt_record_data = (char **)malloc(sizeof(char *) * txt_num);
        for (int i = 0; i < txt_num; ++i)
        {
            txt_record_data[i] = (char *)calloc(5000, sizeof(char));
        }
        unsigned char *pqtlsa_record_all[tlsa_num];
        unsigned char **pqtlsa_record_all_ptr = pqtlsa_record_all;

        char pqtlsa_record[BUF_SIZE];
        unsigned char query_pqtlsa_buffer[tlsa_num][4096];
        int pqtlsa_len[tlsa_num];
        int *pqtlsa_len_ptr = pqtlsa_len;

        // to avoid TCP retry after UDP failure
        struct arg_struct args;
        args.argc = argc;
        args.argv = argv;
        args.addr = &addr;
        args.sock = sock;
        args.is_start = &is_start;

        pthread_t ptid;
        pthread_create(&ptid, NULL, &thread_init_tcp_sync, (void *)&args);
        struct arg_struct2 args2[tlsa_num];

        for (int i = 0; i < tlsa_num; ++i)
        {
            args2[i].argc = argc;
            args2[i].argv = argv;
            args2[i].pqtlsa_num = i + 1;
            args2[i].pqtlsa_query_buffer = query_pqtlsa_buffer[i];
            args2[i].buffer_size = sizeof(query_pqtlsa_buffer[i]);
            args2[i].pqtlsa_record_len = pqtlsa_len + i;
            args2[i].pqtlsa_record_all = pqtlsa_record_all + i;
            args2[i].is_start = &is_start;
        }
        int total_txt_num[50];
        int total_tlsa_num[50];
        for (int i = 0; i < 50; i++)
        {
            total_txt_num[i] = -1;
        }
        int *txt_recovery = total_txt_num;

        struct arg_struct3 args3[txt_num];

        for (int i = 0; i < txt_num; ++i)
        {
            args3[i].argc = argc;
            args3[i].argv = argv;
            args3[i].txt_num = i + 1;
            args3[i].total_txt_num = &txt_recovery;
            args3[i].txt_query_buffer = query_txt_buffer[i];
            args3[i].txt_record_data = txt_record_data[i];
        }
        pthread_t ptid_pqtlsa[tlsa_num];


        pthread_mutex_init(&mutex, NULL);
        clock_gettime(CLOCK_MONOTONIC, &begin);
        double starting2 = (begin.tv_sec) + (begin.tv_nsec) / 1000000000.0;

        for (int i = 0; i < tlsa_num; ++i)
        {
            pthread_create(ptid_pqtlsa + i, NULL, &thread_tlsa_query, (void *)(args2 + i));
        }
        // A thread is created when a program is executed, and is executed when a user triggers
        //  sleep(1);
        is_start = 1;
        sleep(1);
        is_start = 1;

        clock_gettime(CLOCK_MONOTONIC, &begin);
        double starting = (begin.tv_sec) + (begin.tv_nsec) / 1000000000.0;  

        pthread_t ptid_txt[txt_num];
        for (int i = 0; i < txt_num; ++i)
        {
            pthread_create(ptid_txt + i, NULL, &thread_txt_query, (void *)(args3 + i));
        }

        for (int i = 0; i < txt_num; ++i)
        {
            pthread_join(ptid_txt[i], NULL);
        }
        
        clock_gettime(CLOCK_MONOTONIC, &begin);
        double ending = (begin.tv_sec) + (begin.tv_nsec) / 1000000000.0;   
        txtquerytime = ending - starting;

        for (int i = 0; i < tlsa_num; ++i)
        {
            pthread_join(ptid_pqtlsa[i], (void **)(pqtlsa_len + i));
        }
        clock_gettime(CLOCK_MONOTONIC, &begin);
        ending = (begin.tv_sec) + (begin.tv_nsec) / 1000000000.0;   
        tlsaquerytime = ending - starting2 -1;


        // pthread_join(ptid_txt[0], NULL);

        pthread_mutex_destroy(&mutex);
        clock_gettime(CLOCK_MONOTONIC, &begin);
        ending = (begin.tv_sec) + (begin.tv_nsec) / 1000000000.0;   
        tlsaquerytime = ending - starting2 -1;

        printf("total_txt_num:");
        for (int i = 0; i < txt_num; i++)
        {
            printf("%d", total_txt_num[i]);
        }
        printf("\n");

        char active_txt[sizeof(char) * 70000];
        strcpy(active_txt, txt_record_data[0]);

        // printf("txt_passive_data: %s\n", txt_passive.txt_record_data);
        char *tmp;
        tmp = strtok(active_txt, " ");
        int txt_num_total = atoi(tmp);
        tmp = strtok(NULL, " ");
        int tlsa_num_total = atoi(tmp);

        printf("txt_num_total %d\n", txt_num_total);
        printf("tlsa_num_total %d\n", tlsa_num_total);
        int txt_num_aid = 0;
        int tlsa_num_aid = 0;

        int tlsa_recover = TLSA_NUM;
        if (tlsa_num_total > TLSA_NUM)
            tlsa_recover = tlsa_num_total;

        struct arg_struct2 args2_aid[tlsa_num_total];
        if (tlsa_num_total > TLSA_NUM)
        {
            printf("get more tlsa records\n");
            for (int i = 0; i < tlsa_num; ++i)
            {
                args2_aid[i].argc = args2[i].argc;
                args2_aid[i].argv = args2[i].argv;
                args2_aid[i].pqtlsa_num = args2[i].pqtlsa_num;
                args2_aid[i].pqtlsa_query_buffer = args2[i].pqtlsa_query_buffer;
                args2_aid[i].buffer_size = args2[i].buffer_size;
                args2_aid[i].pqtlsa_record_len = args2[i].pqtlsa_record_len;
                args2_aid[i].pqtlsa_record_all = args2[i].pqtlsa_record_all;
                args2_aid[i].is_start = args2[i].is_start;
            }
        }

        ///////////////////////////////////////
        if (txt_num_total > TXT_NUM)
        {
            txt_num_aid = txt_num_total - TXT_NUM;

            unsigned char query_txt_buffer_aid[txt_num_aid][5000];
            char **txt_record_data_aid;
            txt_record_data_aid = (char **)malloc(sizeof(char *) * txt_num_aid);
            for (int i = 0; i < txt_num_aid; ++i)
            {
                txt_record_data_aid[i] = (char *)malloc(sizeof(char) * 50000);
                txt_record_data_aid[i][0] = '\0';
            }

            struct arg_struct3 args3_aid[txt_num_aid];

            for (int i = 0; i < txt_num_aid + 1; ++i)
            {
                args3_aid[i].argc = argc;
                args3_aid[i].argv = argv;
                args3_aid[i].txt_num = i + TXT_NUM; // additional records only
                args3_aid[i].total_txt_num = &txt_recovery;
                args3_aid[i].txt_query_buffer = query_txt_buffer_aid[i];
                args3_aid[i].txt_record_data = txt_record_data_aid[i];
            }

            pthread_t ptid_txt[txt_num_aid];
            //  pthread_mutex_init(&mutex,NULL);
            for (int i = 0; i < txt_num_aid; ++i)
            {
                pthread_create(ptid_txt + i, NULL, &thread_txt_query_retry, (void *)(args3_aid + i));
            }

            for (int i = 0; i < txt_num_aid; ++i)
            {
                pthread_join(ptid_txt[i], NULL);
            }

            //  pthread_mutex_destroy(&mutex);
            *txt_record_all = '\0';
            txt_record_all_aid[0] = '\0';
          //  printf("txt_record_all_aid: %s\n", txt_record_all_aid);
            for (int i = 0; i < txt_num_aid; i++)
            {
                strcat(txt_record_all_aid, txt_record_data_aid[i]);
            }
         //   printf("txt_record_all_aid2: %s\n", txt_record_all_aid);
            for (int i = 0; i < txt_num_aid; ++i)
            {
                free(txt_record_data_aid[i]);
            }
                    
            clock_gettime(CLOCK_MONOTONIC, &begin);
            ending = (begin.tv_sec) + (begin.tv_nsec) / 1000000000.0;   
            txtquerytime = ending - starting;
        }

      //  printf("txt_record_data 1: %s\n", txt_record_data[0]);
        // printf("txt_record_data 2: %s\n", txt_record_data[1]);

        if (tlsa_num_total > TLSA_NUM)
        {
            printf("get more tlsa records2\n");
            tlsa_num_aid = tlsa_num_total - TLSA_NUM;

            char pqtlsa_record[BUF_SIZE];
            pqtlsa_record_all_aid = malloc(sizeof(*pqtlsa_record_all_aid) * tlsa_num_total);
            if (!pqtlsa_record_all_aid)
            {
                // 메모리 할당 실패 처리
                exit(1);
            }

            unsigned char query_pqtlsa_buffer_aid[tlsa_num_total][4096];
            int pqtlsa_len_aid[tlsa_num_total];
            int *pqtlsa_len_aid_ptr = pqtlsa_len_aid;

            for (int i = 0; i < tlsa_num_aid; ++i)
            {
                args2_aid[i + TLSA_NUM].argc = argc;
                args2_aid[i + TLSA_NUM].argv = argv;
                args2_aid[i + TLSA_NUM].pqtlsa_num = TLSA_NUM + i;
                args2_aid[i + TLSA_NUM].pqtlsa_query_buffer = query_pqtlsa_buffer_aid[i + TLSA_NUM];
                args2_aid[i + TLSA_NUM].buffer_size = sizeof(query_pqtlsa_buffer_aid[i + TLSA_NUM]);
                args2_aid[i + TLSA_NUM].pqtlsa_record_len = pqtlsa_len_aid + i + TLSA_NUM;
                args2_aid[i + TLSA_NUM].pqtlsa_record_all = pqtlsa_record_all_aid + i + TLSA_NUM;
                args2_aid[i + TLSA_NUM].is_start = &is_start;
            }

            pthread_t ptid_pqtlsa_aid[tlsa_num_aid];

            // pthread_mutex_init(&mutex,NULL);

            for (int i = 0; i < tlsa_num_aid; ++i)
            {
                pthread_create(ptid_pqtlsa_aid + i, NULL, &thread_tlsa_query_retry, (void *)(args2_aid + i + TLSA_NUM));
            }

            for (int i = 0; i < tlsa_num_aid; ++i)
            {
                pthread_join(ptid_pqtlsa_aid[i], (void **)(pqtlsa_len_aid + i + TLSA_NUM));
            }
            clock_gettime(CLOCK_MONOTONIC, &begin);
            ending = (begin.tv_sec) + (begin.tv_nsec) / 1000000000.0;   
            tlsaquerytime = ending - starting2 -1;
            for (int i = 0; i < tlsa_num_total; i++)
            {
                printf("Length of record aid %d: %d\n", i, *(pqtlsa_len_aid_ptr + i));
            }

            for (int i = 0; i < TLSA_NUM; i++)
            {
        //        printf("11111\n");

                pqtlsa_len_aid[i] = pqtlsa_len[i];
                pqtlsa_record_all_aid[i] = pqtlsa_record_all[i];
            }

            for (int i = 0; i < tlsa_num_total; i++)
            {
     //           printf("Length of record aid %d: %d\n", i, pqtlsa_len_aid[i]);
            }
            pqtlsa_len_ptr = pqtlsa_len_aid_ptr;

            pqtlsa_record_all_ptr = pqtlsa_record_all_aid;
        }
        // pthread_mutex_destroy(&mutex);
  

        totalquerytime = ending - starting2 -1;
        // fd
        // printf("ztls_cert: \n%s\n", ztls_cert);

        printf("\n\n");

        char txt_record_except_signature[BUF_SIZE] = "";
        for (int i = 0; i < txt_num; i++)
        {
   //         printf("txt_record_data[%d]: %s\n", i, txt_record_data[i]);
            strcat(txt_record_all, txt_record_data[i]);
        }
        if (txt_record_all_aid != NULL)
        {
//            printf("cat record all aid\n");
            strcat(txt_record_all, txt_record_all_aid);
        }

        for (int i = 0; i < tlsa_num_total; i++)
        {
//            printf("Length of record %d: %d\n", i, *(pqtlsa_len_ptr + i));
        }

        /*
            for (int i = 0; i < tlsa_num_total; i++) {
            printf("Data %d: ", i);
            for (int j = 0; j < *(pqtlsa_len_ptr+i); j++) {
                printf("%02x ", pqtlsa_record_all[i][j]); // 각 바이트를 16진수 형태로 출력
            }
            printf("\n");
        }
        */

        unsigned char *based64_out;
        based64_out = hex_to_base64(pqtlsa_record_all_ptr, pqtlsa_len_ptr, hex_buffer, tlsa_num_total);
        // based64_out = hex_to_base64(tlsa2_record_all, tlsa2_len, hex_buffer);
        char newline2[4] = "\n";
        char *ztls_cert;
        ztls_cert = (char *)malloc(sizeof(char) * 70000);
        // for(int j = 0; j < 916-64 ; j=j+64){ 908

        for (int j = 0; j < 5312; j = j + 64)
        {
            strncat(ztls_cert, based64_out + j, 64);
            strcat(ztls_cert, newline2);
            // printf("hex_out_cert: %s", ztls_cert);
        }
//        printf("ztls_cert:\n%s", ztls_cert);

        //  for (int i = 0; i < tlsa_num_aid; ++i) {
        //    free(pqtlsa_record_all_aid[i]); // 개별 요소(가 동적으로 할당된 경우) 해제
        //  }
        free(pqtlsa_record_all_aid);

//        printf("txt_record_all: %s\n", txt_record_all);
        for (int i = 0; i < txt_num; ++i)
        {
            free(txt_record_data[i]);
        }
        free(txt_record_data);
        // printf("txt_record_all:\n%s\n\n",txt_record_all);
        load_dns_info2(&dns_info, txt_record_except_signature, txt_record_all, ztls_cert);
        SSL_CTX_add_custom_ext(ctx, 53, SSL_EXT_CLIENT_HELLO, dns_info_add_cb, dns_info_free_cb, NULL, NULL, NULL); // extentionTye = 53, Extension_data = dns_cache_id
        /*
        if (dns_info.KeyShareEntry.group == 570)
        { // keyshare group : 0x001d(X25519)
            // SSL_CTX_set1_groups_list(ctx, "X25519");
            ssl = SSL_new(ctx);
            SSL_set_ex_data(ssl, my_idx, time_data);

            if (!SSL_set1_groups_list(ssl, "kyber512"))
                error_handling("fail to set kyber512");
            // for demo, we will add other groups later.
            // switch
            // P-256, P-384, P-521, X25519, X448, ffdhe2048, ffdhe3072, ffdhe4096, ffdhe6144, ffdhe8192
        }
        */
        dns_info.KeyShareEntry.group = 570;
        int result_cb = SSL_CTX_add_client_custom_ext(ctx, 65280, ext_add_cb, ext_free_cb, NULL, ext_parse_cb, NULL);
        ssl = SSL_new(ctx);
        SSL_set_ex_data(ssl, my_idx, timing_data);
        if (!SSL_set1_groups_list(ssl, "kyber512"))
            error_handling("fail to set kyber512");


        free(txt_record_all);

        // ssl = SSL_new(ctx);
        //  dfSSL_set_wfd(ssl, DNS); // fd : 1 => ZTLS, fd : 0 => TLS 1.3

        printf("return of ssl set wfd: %d\n", SSL_set_wfd(ssl, DNS));
        // Check timestamp Valid
        if (dns_info.DNSCacheInfo.validity_period_not_before < time(NULL) && dns_info.DNSCacheInfo.validity_period_not_after > time(NULL))
        {
            printf("Valid Period\n");
        }
        else
        {
            printf("Not Valid Period\n");
        }

        //  X509_print_ex_fp(stdout, dns_info.cert, XN_FLAG_COMPAT, X509_FLAG_COMPAT);
        printf("return of server public key: %d\n", SSL_use_PrivateKey(ssl, dns_info.KeyShareEntry.skey)); // set server's keyshare // this function is modified
        verify_self_signed_cert(dns_info.cert);
        BIO *bio_file = BIO_new(BIO_s_file());
        const char *cert_filename = "../dns/cert/dilithium5_crt.pem";
        BIO_read_filename(bio_file, cert_filename);  // 인증서 파일 경로
        dns_info.cert = PEM_read_bio_X509(bio_file, NULL, NULL, NULL);


        printf("return of ssl_use_certificate: %d\n", SSL_use_certificate(ssl, dns_info.cert)); // set sever's cert and verify cert_chain // this function is modified
        if (dns_info.CertVerifyEntry.signature_algorithms == 65184)                             // rsa pss rsae sha256 0x0804 //dilithium2 65184
        {
            strcat(txt_record_except_signature, "\n");
            printf("txt_record_except_signature\n");
     //       printf("%s", txt_record_except_signature);

            strcat(dns_info.CertVerifyEntry.cert_verify, "\n");
            // printf("\ndns_info.CertVerifyEntry.cert_verify\n");
            // printf("%s",dns_info.CertVerifyEntry.cert_verify );
            SSL_export_keying_material(ssl, (unsigned char *)txt_record_except_signature, 0, NULL, 0,
                                       dns_info.CertVerifyEntry.cert_verify, BUF_SIZE, 0); // cert verify: signature of DNS cache info check. // this function is modified
        }                                                                                  // for demo, we will only support rsa pss rsae_sha256

        pthread_join(ptid, NULL);
    }
    else
    {
        is_start = 1;
        init_tcp_sync(argc, argv, &addr, sock, &is_start);
        ssl = SSL_new(ctx);
        SSL_set_ex_data(ssl, my_idx, timing_data);
        if (!SSL_set1_groups_list(ssl, "kyber512"))
            error_handling("fail to set kyber512");
        SSL_set_wfd(ssl, DNS); // fd : 1 => ZTLS, fd : 0 => TLS 1.3
    }
    // threads join

    SSL_set_fd(ssl, sock);
    /*
     * handshake start
     */
    configure_connection(ssl); // SSL do handshake
    clock_gettime(CLOCK_MONOTONIC, &total);
    double execution_time = (total.tv_sec) + (total.tv_nsec) / 1000000000.0; // for bench
    char message[BUF_SIZE];
    int str_len;
    struct timespec send_ctos, receive_ctos;
   // printf("callback: %f\n", time_data->hand_time);

    if (!DNS)
    { // normal TLS 1.3
        memcpy(message, "hello\n", 6);

        SSL_write(ssl, message, strlen(message));
        clock_gettime(CLOCK_MONOTONIC, &send_ctos);
        printf("send : %s", message);
        printf("%f\n", (send_ctos.tv_sec) + (send_ctos.tv_nsec) / 1000000000.0);

        if ((str_len = SSL_read(ssl, message, BUF_SIZE - 1)) <= 0)
        {
            printf("error\n");
        }
        message[str_len] = 0;
        clock_gettime(CLOCK_MONOTONIC, &receive_ctos);
        printf("Message from server: %s", message);
        printf("%f\n", (receive_ctos.tv_sec) + (receive_ctos.tv_nsec) / 1000000000.0);
        clock_gettime(CLOCK_MONOTONIC, &total);
        execution_time = (total.tv_sec) + (total.tv_nsec) / 1000000000.0; // for bench
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
    // double execution_time = (total.tv_sec) + (total.tv_nsec) / 1000000000.0;
    txtquerytime = txt_after - txt_before;
    tlsaquerytime = tlsa_after - tlsa_before;
    totalquerytime = MAX(txt_after, tlsa_after) - MIN(txt_before, a_before);

    if(DNS)
        total_runtime = total_runtime-1; //elemination sleeptime on code
    //fprintf(fp, "%f\n", total_runtime);
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
static void init_tcp_sync(int argc, char *argv[], struct sockaddr_storage *addr, int sock, int *is_start)
{
    while (*is_start < 0)
    { // for prototyping. next, use signal.
        // nothing
    }
    struct timespec begin1, begin2;
    clock_gettime(CLOCK_MONOTONIC, &begin1);
    printf("start A and AAAA DNS records query : %f\n", (begin1.tv_sec) + (begin1.tv_nsec) / 1000000000.0);
    start_time = (begin1.tv_sec) + (begin1.tv_nsec) / 1000000000.0;
    printf("%s, %s\n", argv[1], argv[2]);
    // size_t len = resolve_hostname(argv[1], argv[3], addr);
    size_t len = resolve_hostname(argv[1], argv[2], addr);
    clock_gettime(CLOCK_MONOTONIC, &begin2);
    printf("complete A and AAAA DNS records query : %f\n", (begin2.tv_sec) + (begin2.tv_nsec) / 1000000000.0);
    double ending = (begin2.tv_sec) + (begin2.tv_nsec) / 1000000000.0;
    aquerytime = ending - start_time;
    a_before = start_time;
    if (connect(sock, (struct sockaddr *)addr, len) < 0)
    {
        error_handling("connect() error!");
    }
    else
    {
        clock_gettime(CLOCK_MONOTONIC, &begin2);
        printf("complete TCP Sync : %f\n", (begin2.tv_sec) + (begin2.tv_nsec) / 1000000000.0);
    }
}
static int dns_query_with_timeout(const char *domain, int type, unsigned char *answer)
{
    struct __res_state res_state;
    // ns_type type;
    // type= ns_t_txt;

    if (res_ninit(&res_state) < 0)
    {
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

static int txt_query_retry(char *argv[], int txt_num, int **total_txt_num, unsigned char query_txt_buffer[], unsigned char *txt_record_all)
{
    int response = -1;
    ns_type type;
    type = ns_t_txt;
    ns_msg nsMsg;
    ns_rr rr;
    int retry_count = 2;
    char query_num[20];
    char query_url[20] = "ebox-";
    char query_url_postfix[20] = ".esplab.io";
    sprintf(query_num, "%d", txt_num);
    strcat(query_url, argv[3]);
    strcat(query_url, ".");
    strcat(query_url, query_num);
    strcat(query_url, query_url_postfix);
    for (int i = 0; i < retry_count; ++i)
    {
        printf("Attempt %d to query TXT record for %s\n", i + 1, query_url);
        clock_gettime(CLOCK_MONOTONIC, &point);
        if(txt_before == 0)
        txt_before = (point.tv_sec) + (point.tv_nsec) / 1000000000.0;

        response = dns_query_with_timeout(query_url, ns_t_txt, query_txt_buffer);
        clock_gettime(CLOCK_MONOTONIC, &point);
        txt_after = (point.tv_sec) + (point.tv_nsec) / 1000000000.0;

        if (response >= 0)
        {
            // 성공적으로 응답 받음
            printf("Successfully received TXT response\n");
            ns_initparse(query_txt_buffer, response, &nsMsg);
            // ns_parserr(&nsMsg, ns_s_an, 0, &rr);
            u_char const *rdata = (u_char *)(ns_rr_rdata(rr) + 1);
            //*txt_record_all = (unsigned char*)rdata;
            int rr_count = ns_msg_count(nsMsg, ns_s_an);

            int offset = 0;
            for (int i = 0; i < rr_count; i++)
            {
                if (ns_parserr(&nsMsg, ns_s_an, i, &rr) == 0)
                {
                    if (ns_rr_type(rr) == ns_t_txt)
                    {
                        u_char *rdata = ns_rr_rdata(rr);
                        int rdata_len = ns_rr_rdlen(rr);
                        u_char *end = rdata + rdata_len;
                        // TXT 레코드의 첫 번째 바이트는 길이를 나타냅니다.
                        while (rdata < end)
                        {
                            int txt_len = *rdata++;
                            // snprintf를 사용하여 txt_record_all에 문자열 추가
                            if (offset + txt_len < 7000 - 1)
                            { // 버퍼 크기를 초과하지 않도록 확인
                                snprintf(txt_record_all + offset, txt_len + 1, "%.*s", txt_len, (char *)rdata);
                                offset += txt_len;
                                rdata += txt_len;
                            }
                        }
                    }
                }
            }
            txt_record_all[offset] = '\0';
            return 0;
        }
        else
        {
            printf("No response, retrying...\n");
        }
    }
    ns_initparse(query_txt_buffer, response, &nsMsg);
    // ns_parserr(&nsMsg, ns_s_an, 0, &rr);
    u_char const *rdata = (u_char *)(ns_rr_rdata(rr) + 1);
    //*txt_record_all = (unsigned char*)rdata;
    int rr_count = ns_msg_count(nsMsg, ns_s_an);

    int offset = 0;
    for (int i = 0; i < rr_count; i++)
    {
        if (ns_parserr(&nsMsg, ns_s_an, i, &rr) == 0)
        {
            if (ns_rr_type(rr) == ns_t_txt)
            {
                u_char *rdata = ns_rr_rdata(rr);
                int rdata_len = ns_rr_rdlen(rr);
                u_char *end = rdata + rdata_len;
                // TXT 레코드의 첫 번째 바이트는 길이를 나타냅니다.
                while (rdata < end)
                {
                    int txt_len = *rdata++;
                    // snprintf를 사용하여 txt_record_all에 문자열 추가
                    if (offset + txt_len < 7000 - 1)
                    { // 버퍼 크기를 초과하지 않도록 확인
                        snprintf(txt_record_all + offset, txt_len + 1, "%.*s", txt_len, (char *)rdata);
                        offset += txt_len;
                        rdata += txt_len;
                    }
                }
            }
        }
    }
    txt_record_all[offset] = '\0';
    printf("No response\n");
    return -1;

    // 모든 시도 실패
}

static int txt_query(char *argv[], int txt_num, int **total_txt_num, unsigned char query_txt_buffer[], unsigned char *txt_record_all)
{

    char query_num[20];
    char query_url[20] = "ebox-";
    char query_url_postfix[20] = ".esplab.io";
    ns_type type;
    type = ns_t_txt;
    ns_msg nsMsg;
    ns_rr rr;
    int response;
    sprintf(query_num, "%d", txt_num - 1);
    strcat(query_url, argv[3]);
    strcat(query_url, ".");
    strcat(query_url, query_num);
    strcat(query_url, query_url_postfix);
    struct timespec begin;
    clock_gettime(CLOCK_MONOTONIC, &begin);
    // is_start =1; //user trigger
    printf("start : %f\n", (begin.tv_sec) + (begin.tv_nsec) / 1000000000.0);
    clock_gettime(CLOCK_MONOTONIC, &begin);
    printf("start DNS TXT query: %f\n", (begin.tv_sec) + (begin.tv_nsec) / 1000000000.0);
    printf("query_url in txt query: %s\n", query_url);
    if(txt_before == 0)
    txt_before = (begin.tv_sec) + (begin.tv_nsec) / 1000000000.0;

    response = res_search(query_url, C_IN, type, query_txt_buffer, 4096);
    clock_gettime(CLOCK_MONOTONIC, &begin);
    txt_after = (begin.tv_sec) + (begin.tv_nsec) / 1000000000.0;
    // response = res_search(argv[txt_num+2], C_IN, type, query_txt_buffer, 4096);
    //  log
    clock_gettime(CLOCK_MONOTONIC, &begin);
    printf("complete DNS TXT query : %f\n", (begin.tv_sec) + (begin.tv_nsec) / 1000000000.0);
    if (response < 0)
    {
        printf("Error looking up service: TXT %d\n", txt_num);
        **total_txt_num = txt_num;
        *total_txt_num += 1;
        return 0;
    }

    ns_initparse(query_txt_buffer, response, &nsMsg);
    // ns_parserr(&nsMsg, ns_s_an, 0, &rr);
    u_char const *rdata = (u_char *)(ns_rr_rdata(rr) + 1);
    //*txt_record_all = (unsigned char*)rdata;
    int rr_count = ns_msg_count(nsMsg, ns_s_an);

    int offset = 0;

    int i;
    for (i = 0; i < rr_count; i++)
    {
        if (ns_parserr(&nsMsg, ns_s_an, i, &rr) == 0)
        {
            if (ns_rr_type(rr) == ns_t_txt)
            {
                u_char *rdata = ns_rr_rdata(rr);
                // printf("rdata: %s\n", rdata);
                int rdata_len = ns_rr_rdlen(rr);
                u_char *end = rdata + rdata_len;
                while (rdata < end)
                {
                    int txt_len = *rdata;
                    rdata++;
                    snprintf(txt_record_all + offset, 7000 - offset, "%.*s ", txt_len, (char *)rdata);
                    offset += txt_len;
                    rdata += txt_len;
                }
            }
        }
    }
    // strcat(*txt_record_all,'\0');
    // printf("txt_record_all: %s\n", txt_record_all);
}

static int tlsa_query(char *argv[], int tlsa_num, unsigned char query_buffer[], int buffer_size, unsigned char **tlsa_record_all, int *is_start)
{

    while (*is_start < 0)
    { // for prototyping. next, use signal.
        // nothing
    }
    printf("pqtlsa_num: %d\n", tlsa_num - 1);
    char query_num[20];
    char query_url[100] = "_443._udp.ebox-";
    char query_url_postfix[20] = ".esplab.io";
    sprintf(query_num, "%d", tlsa_num - 1);
    strcat(query_url, argv[3]);
    strcat(query_url, ".");
    strcat(query_url, query_num);
    strcat(query_url, query_url_postfix);
    printf("query_url in tlsa query: %s\n", query_url);

    // char query_url[100] = "_443._udp.";
    // strcat(query_url,argv[tlsa_num+2]);  //dilithium2
    ns_type type2;
    type2 = ns_t_tlsa;
    ns_msg nsMsg;
    ns_rr rr;
    int response;

    struct timespec begin;
    clock_gettime(CLOCK_MONOTONIC, &begin);
    printf("start DNS PQTLSA query: %f\n", (begin.tv_sec) + (begin.tv_nsec) / 1000000000.0);
    // printf("start DNS TLSA query:\n");
    if(tlsa_before == 0)
    tlsa_before = (begin.tv_sec) + (begin.tv_nsec) / 1000000000.0;
    response = res_search(query_url, C_IN, type2, query_buffer, buffer_size);
    // log

    clock_gettime(CLOCK_MONOTONIC, &begin);
    tlsa_after = (begin.tv_sec) + (begin.tv_nsec) / 1000000000.0;
    printf("complete DNS PQTLSA query : %f\n", (begin.tv_sec) + (begin.tv_nsec) / 1000000000.0);
    // printf("complete DNS TLSA query :\n");

    if (response < 0)
    {
        printf("Error looking up service: TLSA \n");
        *tlsa_record_all = NULL; // 쿼리 실패 시 NULL 할당
    }
    ns_initparse(query_buffer, response, &nsMsg);
    ns_parserr(&nsMsg, ns_s_an, 0, &rr);
    u_char const *rdata = (u_char *)(ns_rr_rdata(rr) + 3);

    *tlsa_record_all = (unsigned char *)rdata;

    int len = ns_rr_rdlen(rr);

    return len - 3;
}

static int tlsa_query_retry(char *argv[], int tlsa_num, unsigned char query_buffer[], int buffer_size, unsigned char **tlsa_record_all, int *is_start)
{
    int retry_count = 2;
    while (*is_start < 0)
    { // for prototyping. next, use signal.
        // nothing
    }
    printf("pqtlsa_num: %d\n", tlsa_num - 1);
    char query_num[20];
    char query_url[100] = "_443._udp.ebox-";
    char query_url_postfix[20] = ".esplab.io";
    sprintf(query_num, "%d", tlsa_num);
    strcat(query_url, argv[3]);
    strcat(query_url, ".");
    strcat(query_url, query_num);
    strcat(query_url, query_url_postfix);
    printf("query_url in tlsa query: %s\n", query_url);

    // char query_url[100] = "_443._udp.";
    // strcat(query_url,argv[tlsa_num+2]);  //dilithium2
    ns_type type2;
    type2 = ns_t_tlsa;
    ns_msg nsMsg;
    ns_rr rr;
    int response;
    int len;

    struct timespec begin;
    clock_gettime(CLOCK_MONOTONIC, &begin);
    printf("start DNS PQTLSA query: %f\n", (begin.tv_sec) + (begin.tv_nsec) / 1000000000.0);
    // printf("start DNS TLSA query:\n");
    for (int i = 0; i < retry_count; ++i)
    {
        printf("Attempt %d to query TLSA record for %s\n", i + 1, query_url);
        clock_gettime(CLOCK_MONOTONIC, &begin);
        if(tlsa_before == 0)
        tlsa_before = (begin.tv_sec) + (begin.tv_nsec) / 1000000000.0;

        response = dns_query_with_timeout(query_url, type2, query_buffer);
        clock_gettime(CLOCK_MONOTONIC, &begin);
        tlsa_after = (begin.tv_sec) + (begin.tv_nsec) / 1000000000.0;

        if (response >= 0)
        {
            printf("Successfully received TLSA response\n");
            ns_initparse(query_buffer, response, &nsMsg);
            ns_parserr(&nsMsg, ns_s_an, 0, &rr);
            u_char const *rdata = (u_char *)(ns_rr_rdata(rr) + 3);

            *tlsa_record_all = (unsigned char *)rdata;
            len = ns_rr_rdlen(rr);
            clock_gettime(CLOCK_MONOTONIC, &begin);
            printf("complete DNS PQTLSA query : %f\n", (begin.tv_sec) + (begin.tv_nsec) / 1000000000.0);
            return len - 3;
        }
        else
        {
            printf("No response, retrying...\n");
        }
    }

    // response = res_search(query_url, C_IN, type2, query_buffer, buffer_size);
    //  log

    // printf("complete DNS TLSA query :\n");
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
    *tlsa_record_all = NULL;
    return len - 3;
}
static void init_openssl()
{
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

static int load_dns_info2(struct DNS_info *dp, char *truncated_dnsmsg_out, char *dnsmsg, char *ztls_cert)
{
    BIO *bio_key, *bio_cert;
    char *tmp;
    char *cert_len;
    // char publickey_prefix[5000] = "-----BEGIN PUBLIC KEY-----\n";
    char *publickey_prefix;
    publickey_prefix = (char *)calloc(6000, sizeof(char));
    memset(publickey_prefix, 0, sizeof(char) * 6000);
    strcpy(publickey_prefix, "-----BEGIN PUBLIC KEY-----\n");
    // printf("%s\n", publickey_prefix);

    char publickey_postfix[30] = "-----END PUBLIC KEY-----\n";
    char certificate_prefix[BUF_SIZE] = "-----BEGIN CERTIFICATE-----\n";
    char certificate_postfix[30] = "-----END CERTIFICATE-----\n";

    char *certificate_prefix2;
    certificate_prefix2 = (char *)calloc(70000, sizeof(char));

    strcat(certificate_prefix2, "-----BEGIN CERTIFICATE-----\n");

    // char certificate_prefix2[BUF_SIZE] = "-----BEGIN CERTIFICATE-----\n";
    char certificate_postfix2[30] = "-----END CERTIFICATE-----\n";
    char txt_record_signature[BUF_SIZE];
    char newline[4] = "\n";
    char *ztls_version = "0"; // v=pqztls_1
    char *ztls_cert_copy;
    ztls_cert_copy = (char *)calloc(70000, sizeof(char));
    // printf("ztls_cert2: \n%s\n\n", ztls_cert);
    int k = 0;
    for (int i = 0; *(ztls_cert + i) != '\0'; ++i)
    {
        if (*(ztls_cert + i) != '\n')
        {
            ztls_cert_copy[k++] = *(ztls_cert + i);
        }
    }
    ztls_cert_copy[k] = '\0';

    // printf("str :\n%s\n", str);
   // printf("ztls_cert_copy: \n%s\n\n", ztls_cert_copy);
    // v=ztls1 check
    // printf("txt records:\n %s\n", dnsmsg);
    char txt_record_except_signature[BUF_SIZE];
    tmp = strtok(dnsmsg, " ");
    strcat(txt_record_except_signature, tmp);
    tmp = strtok(NULL, " ");
    strcat(txt_record_except_signature, tmp);
    tmp = strtok(NULL, " ");
    printf("version: %s\n", tmp);
    strcat(txt_record_except_signature, tmp);
    // strtok(NULL, " ");
    if (0 != strcmp(tmp, ztls_version))
    {
        printf("DNS TXT record's ZTLS version error\n");
    }

    // load dns cache info
    tmp = strtok(NULL, " "); // algoritm ID 0 : TLS 1.3, 1 : KEMTLS, 2 : QUIC
    int algorithm_ID = atoi(tmp);
    printf("algorithm_ID: %d\n", algorithm_ID);
    strcat(txt_record_except_signature, tmp);
    // printf("txt_record_except_signature: %s\n",txt_record_except_signature);
    tmp = strtok(NULL, " "); // period_not_before
    dp->DNSCacheInfo.validity_period_not_before = is_datetime(tmp);
    printf("DNS cache period: %s~", tmp);
    // strtok(NULL," ");
    tmp = strtok(NULL, " "); // period_not_after
    strcat(txt_record_except_signature, tmp);
    dp->DNSCacheInfo.validity_period_not_after = is_datetime(tmp);
    printf("%s\n", tmp);
    // strtok(NULL," ");
    tmp = strtok(NULL, " ");
    char *signature_ID = tmp; //signature ID  0 : dilithium2 ,,,
    printf("signature_ID: %d\n", atoi(signature_ID));
    //strcat(txt_record_except_signature, tmp);
    //dp->DNSCacheInfo.max_early_data_size = strtoul(tmp, NULL, 0);
    // strtok(NULL," ");
    char *signature_length = strtok(NULL, " ");
    int sig_len = atoi(signature_length);
    printf("sig_len: %d\n", sig_len);
    //strcat(txt_record_except_signature, tmp);
    // printf("id: %s\n", tmp);
    //strcat(txt_record_except_signature, tmp);
    // dp->DNSCacheInfo.dns_cache_id = strtoul(tmp, NULL, 0);
    // strtok(NULL," ");
    int skey_dlen = sig_len/180;
    if (sig_len%180 != 0)
        skey_dlen++;
     printf("skey_dlen: %d\n", skey_dlen);
    // load keyshare entry
 //   tmp = strtok(NULL, " ");
    // printf("key num: %s\n", tmp);
  //  strcat(txt_record_except_signature, tmp);
  //  dp->KeyShareEntry.group = strtoul(tmp, NULL, 10);
    // printf("dp->KeyshareEntry.group: %d\n",dp->KeyShareEntry.group);
  //  tmp = strtok(NULL, " ");
   // int skey_dlen = atoi(tmp);
   // printf("skey_dlen: %d\n", skey_dlen);
    // tmp = strtok(NULL," ");
    if (algorithm_ID == 1){ // if KEMTLS
        printf("KEMTLS data detected\n");
    char token_buf[500];
    char *token;
    tmp = strtok(NULL, " ");
    if (token != NULL)
    {
        strncpy(tmp, token, sizeof(tmp) - 1);
    }
    for (int i = 0; i < skey_dlen; i++)
    {
        token = strtok(NULL, " ");
        if (token != NULL)
        {
            // copy txt record chunks if token is not NULL
            strncpy(token_buf, token, sizeof(token_buf) - 1);
            token_buf[sizeof(token_buf) - 1] = '\0';
            strncat(tmp, token_buf, sizeof(tmp) - strlen(tmp) - 1);

            //  printf("tmp #%d %s\n", i, tmp);
        }
        // strcat(tmp,strtok(NULL," "));
        // printf("tmp #%d %s\n",i, tmp);
    }
    // printf("publickey: %s\n\n", tmp);

    strcat(txt_record_except_signature, tmp);

    // strcat(publickey_prefix, tmp);
    //  load publickey
    for (int j = 0; j < 1103; j = j + 64)
    {
        strncat(publickey_prefix, tmp + j, 64);
        strcat(publickey_prefix, "\n");
        // printf("hex_out_cert: %s", hex_out_cert);
    }

    // strcat(publickey_prefix,"\n");
    // strcat(publickey_prefix,tmp);
    strcat(publickey_prefix, publickey_postfix);
    // printf("publickey_prefix: %s\n",publickey_prefix);
    bio_key = BIO_new(BIO_s_mem());
    printf("public key length: %d\n", BIO_puts(bio_key, publickey_prefix));

    PEM_read_bio_PUBKEY(bio_key, &(dp->KeyShareEntry.skey), NULL, NULL);

    ERR_print_errors_fp(stderr);
    if (dp->KeyShareEntry.skey == NULL)
    {
        printf("pem read bio pubkey err\n");
    }
    }
    free(publickey_prefix);
    // load certificate
    /*
    char *begin_cert = "B_CERTIFICATE";
    char *end_cert = "E_CERTIFICATE";
    strcat(txt_record_except_signature, begin_cert);
    */
    //char cert_len = '005312';
    strcat(txt_record_except_signature, "005312");
    strcat(txt_record_except_signature, ztls_cert_copy);
    



    free(ztls_cert_copy);

    //strcat(txt_record_except_signature, end_cert);
    // printf("truncated_dnsmsg_out: %s\n\n", truncated_dnsmsg_out);
    strcat(certificate_prefix2, ztls_cert);
    // printf("certificate_prefix2: %s\n\n", certificate_prefix2);
    strcat(certificate_prefix2, certificate_postfix2);
  //  printf("certificate_prefix2: %s\n\n", certificate_prefix2);

    bio_cert = BIO_new(BIO_s_mem());
    printf("cert length: %d\n", BIO_puts(bio_cert, certificate_prefix2));

    //BIO_puts(bio_cert, certificate_prefix2);

    PEM_read_bio_X509(bio_cert, &(dp->cert), NULL, NULL);

    if (dp->cert == NULL)
    {
        printf("pem read bio cert err\n");
    }

    free(certificate_prefix2);

    // Client Certificate Request Check
    // for demo No Client Certificate Request
    // strtok(NULL," ");
    //tmp = strtok(NULL, " ");
    //strcat(txt_record_except_signature, tmp);
    //printf("Client Certificate Request: %s\n", tmp);

    // strtok(NULL," ");
    //tmp = strtok(NULL, " ");
    // printf("%s\n", tmp);
    strcat(txt_record_except_signature, signature_ID);
    strcat(txt_record_except_signature, signature_length);
   // printf("txt_record_except_signature: %s\n\n", txt_record_except_signature);

    //  load TXT signature (cert verify)
    //printf("signature_algorithms: %s\n", tmp);
    char *sig_ID = "65184";
    dp->CertVerifyEntry.signature_algorithms = strtoul(sig_ID, NULL, 0); // need to fix 
    // strtok(NULL," ");
    tmp = strtok(NULL, " ");
    int i = 0;

    while (i < 100)
    {
    //    printf("fullsignature: #%d  : %s\n", i, tmp);
        strcat(txt_record_signature, tmp); // value (1)
        tmp = strtok(NULL, " ");
        if (tmp == NULL)
        {
            break;
        }

        // strcat(txt_record_signature, newline);

        /*
        strcat(txt_record_signature, tmp);//value (2)
        tmp = strtok(NULL," ");
        if(tmp == NULL)
            break;
        //strcat(txt_record_signature, newline);

        strcat(txt_record_signature, tmp);//value (3)
        //strtok(NULL," ");
        tmp = strtok(NULL," ");

        if(tmp == NULL)
            break;
        strcat(txt_record_signature, tmp);
        //printf("fullsignature %d, %s\n",i, txt_record_signature);
        */
        i++;
    }
    printf("signature read finished!!\n");
    // strcat(txt_record_signature, tmp);
 //   printf("fullsignature %d, %s\n", i, txt_record_signature);

    if (100 <= i)
    {
        printf("SIGNATURE ERROR\n");
    }

    strcpy(truncated_dnsmsg_out, txt_record_except_signature);
    // printf("truncated_dnsmsg_out: %s\n\n", truncated_dnsmsg_out);

    FILE *file;

    // 파일 열기
    file = fopen("example.txt", "r");
    if (file == NULL)
    {
        perror("Error opening file");
        return 1;
    }

    // 파일에서 문자열 읽기
    if (fgets(txt_record_signature, BUF_SIZE, file) != NULL)
    {
        // 성공적으로 읽힌 경우, 문자열 처리
   //     printf("Read string: %s\n", txt_record_signature);
    }
    else
    {
        printf("Failed to read the file.\n");
    }

    // 파일 닫기
    fclose(file);

    strcpy((char *)dp->CertVerifyEntry.cert_verify, txt_record_signature);
  //  printf("cert_verify:\n%s\n", dp->CertVerifyEntry.cert_verify);
    return 0;
}

static SSL_CTX *create_context()
{
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
    if (!ctx)
        error_handling("fail to create ssl context");
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    return ctx;
}
/*
 * verify
 * set version
 */
static void keylog_callback(const SSL *ssl, const char *line)
{
    // printf("==============================================\n");
    // printf("%s\n", line);
}
static size_t resolve_hostname(const char *host, const char *port, struct sockaddr_storage *addr)
{
    struct addrinfo hint;
    memset(&hint, 0, sizeof(struct addrinfo));
    hint.ai_family = AF_INET;
    hint.ai_socktype = SOCK_STREAM;
    hint.ai_protocol = IPPROTO_TCP;
    struct addrinfo *res = 0;
    if (getaddrinfo(host, port, &hint, &res) != 0)
        error_handling("fail to transform address");
    size_t len = res->ai_addrlen;
    memcpy(addr, res->ai_addr, len);
    freeaddrinfo(res);
    return len;
}
static void configure_connection(SSL *ssl)
{
    SSL_set_tlsext_host_name(ssl, "ns1.esplab.io");
    SSL_set_connect_state(ssl);
    if (SSL_do_handshake(ssl) <= 0)
    {
        ERR_print_errors_fp(stderr);
        error_handling("fail to do handshake");
    }
}
static void error_handling(char *message)
{
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

    if (context == SSL_EXT_CLIENT_HELLO)
    {
        *out = (unsigned char *)malloc(sizeof(char *) * 4);
        memcpy((void *)*out, &(&dns_info)->DNSCacheInfo.dns_cache_id, 4);
        *outlen = 4;
    }

    return 1;
}

static void dns_info_free_cb(SSL *s, unsigned int ext_type,
                             unsigned int context,
                             const unsigned char *out,
                             void *add_arg)
{
    OPENSSL_free((unsigned char *)out);
}

static int ext_parse_cb(SSL *s, unsigned int ext_type,
                        const unsigned char *in,
                        size_t inlen, int *al, void *parse_arg)
{
    return 1;
}

static time_t is_datetime(const char *datetime)
{
    // datetime format is YYYYMMDDHHMMSSz
    struct tm time_val;

    strptime(datetime, "%Y%m%d%H%M%Sz", &time_val);

    return mktime(&time_val); // Invalid
}

unsigned char *hex_to_base64(unsigned char **hex_data, int *size, unsigned char hex[], int tlsa_num)
{
    // printf("hex_to_base64 start: %d\n",size_1);
    int dilithium2_crt_len = 0;
    char temp[10];
    unsigned char *temc[tlsa_num];
    unsigned char n;
    size_t input_len = 0;
    for (int i = 0; i < tlsa_num; ++i)
    {
        temc[i] = *(hex_data + i);
        for (int j = 0; j < *(size + i); j++)
        {
            sprintf(temp, "%02X", *(temc[i]));
            strcat(hex, temp);
            temc[i]++;
        }
        input_len += *(size + i);
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

    // printf("size_1:%d\n, size_2:%d\n", size_1,size_2);
    size_t output_len = 200000;
    char *out_buf = malloc(output_len);
    if (!out_buf)
    {
        return out_buf;
    }

    unsigned int digits;
    int d_len;
    int a = 0;
    char *out = out_buf;
    while (*hex_string)
    {

        if (sscanf(hex_string, "%3x%n", &digits, &d_len) != 1)
        {
            /* parse error */
            free(out_buf);
            return NULL;
        }

        switch (d_len)
        {
        case 3:
            *out++ = base64[digits >> 6];
            dilithium2_crt_len++;
            *out++ = base64[digits & 0x3f];
            dilithium2_crt_len++;
            break;
        case 2:
            digits <<= 4;
            *out++ = base64[digits >> 6];
            dilithium2_crt_len++;
            *out++ = base64[digits & 0x3f];
            dilithium2_crt_len++;

            *out++ = '=';
            dilithium2_crt_len++;
            *out++ = '=';
            dilithium2_crt_len++;
            break;
        case 1:
            digits <<= 2;
            *out++ = base64[digits];
            dilithium2_crt_len++;
            *out++ = '=';
            dilithium2_crt_len++;
            //*out++ = '=';
        }
        hex_string += d_len;
    }

    *out++ = '\0';
    // printf("dilithium2_crt_len: %d\n", dilithium2_crt_len);

    return out_buf;
}