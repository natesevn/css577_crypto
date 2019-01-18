#include <cipher.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string>
#include <cstring>
#include <iostream>

using namespace std;

Cipher::Cipher(unsigned char* key) {
	cipherkey = key;
	cipher = aes256;
}

int Cipher::encrypt(unsigned char* plaintext, unsigned char* ciphertext) {
	unsigned char *key = cipherkey;
	unsigned char *iv = (unsigned char *)"0123456789012345";

	int ciphertext_len;
	ciphertext_len = encryptStuff(plaintext, strlen ((char *)plaintext), key, iv,
                            ciphertext);

	return 0;
}

int Cipher::decrypt(unsigned char* plaintext, unsigned char* ciphertext) {
	unsigned char *key = cipherkey;
	unsigned char *iv = (unsigned char *)"0123456789012345";

	int decryptedtext_len;
	decryptedtext_len = decryptStuff(ciphertext, strlen ((char *)ciphertext), key, iv,
    plaintext);

	return 0;
}

int Cipher::decryptStuff(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext) {
	EVP_CIPHER_CTX *ctx;

	int len;
	int plaintext_len;

	// Create and initialise the context 
  	if(!(ctx = EVP_CIPHER_CTX_new())) 
	  	handleErrors();

	// Initialize decryption operation
	if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    	handleErrors();

	// Decrypt given message to provided output
	if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    	handleErrors();
  	plaintext_len = len;

	// Finalize decryption
	if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) 
		handleErrors();
  	plaintext_len += len;

	// Delete context object
	EVP_CIPHER_CTX_free(ctx);

	return plaintext_len;
}

int Cipher::encryptStuff(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext) {
	EVP_CIPHER_CTX *ctx;

	int len;
	int ciphertext_len;

	// Create and initialise the context 
  	if(!(ctx = EVP_CIPHER_CTX_new())) 
		handleErrors();

	// Initialize encryption operation
	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    	handleErrors();

	// Encrypt given message to provided output
	if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    	handleErrors();
	ciphertext_len = len;

	// Finalize encryption
	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) 
		handleErrors();
	ciphertext_len += len;

	// Delete context object
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

void Cipher::handleErrors(void) {
  	ERR_print_errors_fp(stderr);
  	abort();
}