#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/decoder.h>
#include <stdio.h>

void print_public_key_to_string(EVP_PKEY *pkey) {
    BIO *bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        fprintf(stderr, "Error creating BIO\n");
        return;
    }

    if (PEM_write_bio_PUBKEY(bio, pkey)) {
        // Ensure NULL termination
        BIO_write(bio, "\0", 1);

        char *pem_data;
        BIO_get_mem_data(bio, &pem_data);
        printf("%s", pem_data); // Print as a string
    } else {
        fprintf(stderr, "Error writing public key to BIO\n");
    }

    BIO_free(bio);
}

int main() {
    // 공개 키가 저장된 PEM 파일 열기
    FILE *fp = fopen("./dns/cert/kyber512_pubkey.pem", "r");
    if (fp == NULL) {
        fprintf(stderr, "파일을 열 수 없습니다.\n");
        return 1;
    }

    // BIO 생성
    BIO *bio_key = BIO_new_fp(fp, BIO_NOCLOSE);

    // EVP_PKEY 구조체 초기화
    EVP_PKEY *pkey = NULL;

    // OSSL_DECODER 컨텍스트 생성 (PQC를 지원하는 경우에 맞춰 설정)
    OSSL_DECODER_CTX *ctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, "PEM", NULL, NULL, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, NULL, NULL);

    if (ctx != NULL) {
        // BIO로부터 공개 키 디코딩
        if (OSSL_DECODER_from_bio(ctx, bio_key)) {
            // 성공적으로 디코드된 키를 사용
            // 예: 공개 키 정보 출력
            EVP_PKEY_print_public(bio_key, pkey, 0, NULL);
            if(pkey == NULL){
                printf("ern\n");
            }
        } else {
            // 디코드 실패 처리
            fprintf(stderr, "공개 키를 디코드할 수 없습니다.\n");
        }
        OSSL_DECODER_CTX_free(ctx);
    } else {
        // 디코더 컨텍스트 생성 실패 처리
        fprintf(stderr, "디코더 컨텍스트를 생성할 수 없습니다.\n");
    }

    print_public_key_to_string(pkey);

    // 메모리 해제 및 파일 닫기
    EVP_PKEY_free(pkey);
    BIO_free(bio_key);
    fclose(fp);

    return 0;
}
