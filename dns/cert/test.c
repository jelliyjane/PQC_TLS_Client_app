#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

int main() {
    BIO *bio = NULL;
    EVP_PKEY *pubkey = NULL;

    bio = BIO_new_file("CarolPub.pem", "r");
    if (bio == NULL) {
        fprintf(stderr, "Error opening public key file\n");
        goto cleanup;
    }

    PEM_read_bio_PUBKEY(bio, &pubkey, NULL, NULL);
    if (pubkey == NULL) {
        fprintf(stderr, "Error reading public key from PEM file\n");
        goto cleanup;
    }


cleanup:
    if (pubkey != NULL) {
        EVP_PKEY_free(pubkey);
    }
    if (bio != NULL) {
        BIO_free(bio);
    }

    return 0;
}

