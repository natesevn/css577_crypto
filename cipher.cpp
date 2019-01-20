#include <cipher.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <string>
#include <cstring>
#include <iostream>

using namespace std;

Cipher::Cipher(unsigned char* ckey, unsigned char* hkey, unsigned char* iv, string encalgo) {
	cipherkey = ckey;
	hmackey = hkey;
	cipheriv = iv;
	
	algotype = EVP_aes_128_cbc();
	if(encalgo == "aes128") {
		algotype = EVP_aes_128_cbc();
		keySize = aes128KeySize;
		blockSize = aesBlockSize;
		ivSize = aesIVSize;
	} else if(encalgo == "aes256") {
		algotype = EVP_aes_256_cbc();
		keySize = aes256KeySize;
		blockSize = aesBlockSize;
		ivSize = aesIVSize;
	} else if(encalgo == "3des") {
		algotype = EVP_des_ede3_cbc();
		keySize = desKeySize;
		blockSize = desBlockSize;
		ivSize = desIVSize;
	} 
}

int Cipher::encrypt(unsigned char* plaintext, unsigned char* ciphertext, int expectedLen) {
	unsigned char *key = cipherkey;
	unsigned char *iv = cipheriv;

	unsigned char *res = new unsigned char[expectedLen];
	int ciphertext_len;
	ciphertext_len = encryptStuff(plaintext, strlen ((char *)plaintext), key, iv,
                            algotype, res);

	memcpy(ciphertext, res, ciphertext_len);
	delete[] res;

	return ciphertext_len;
}

int Cipher::decrypt(unsigned char* plaintext, unsigned char* ciphertext, int ciphertextLen) {
	unsigned char *key = cipherkey;
	unsigned char *iv = cipheriv;

	unsigned char *res = new unsigned char[ciphertextLen];
	int decryptedtext_len;
	decryptedtext_len = decryptStuff(ciphertext, ciphertextLen, key, iv,
    						algotype, res);
	memcpy(plaintext, res, decryptedtext_len);

	// make sure the string is null terminated to avoid reading too much data
	plaintext[decryptedtext_len] = '\0';
	delete[] res;
	
	return decryptedtext_len;
}

int Cipher::getHmac(unsigned char* ciphertext, int ciphertextLen, unsigned char* hmac) {
	//todo add iv to cipher
	unsigned char* key = hmackey;

  	unsigned char* result = new unsigned char[EVP_MAX_MD_SIZE];
	unsigned int resultLen = 0;

	// Concatenate IV + ciphertext;
	unsigned char* data = new unsigned char[ivSize + ciphertextLen];
	memcpy(data, cipheriv, ivSize);
	memcpy(data+ivSize, ciphertext, ciphertextLen);
 
  	HMAC(EVP_sha256(), key, keySize, data, ciphertextLen, result, &resultLen);

	memcpy(hmac, result, resultLen);

	delete[] result;
	delete[] data;

	return resultLen;
}

int Cipher::decryptStuff(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, const EVP_CIPHER* algo, unsigned char *plaintext) {
	EVP_CIPHER_CTX *ctx;

	int len;
	int plaintext_len;

	// Create and initialise the context 
  	if(!(ctx = EVP_CIPHER_CTX_new())) 
	  	handleErrors();

	// Initialize decryption operation
	if(1 != EVP_DecryptInit_ex(ctx, algo, NULL, key, iv))
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
  unsigned char *iv, const EVP_CIPHER* algo, unsigned char *ciphertext) {
	EVP_CIPHER_CTX *ctx;

	int len;
	int ciphertext_len;

	// Create and initialise the context 
  	if(!(ctx = EVP_CIPHER_CTX_new())) 
		handleErrors();

	// Initialize encryption operation
	if(1 != EVP_EncryptInit_ex(ctx, algo, NULL, key, iv))
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