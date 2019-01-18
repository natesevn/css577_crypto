#ifndef CIPHER_H
#define CIPHER_H

#include <string>
#include <openssl/evp.h>

using namespace std;

class Cipher {
	public:
		int encrypt(unsigned char* plaintext, unsigned char* ciphertext);
		int decrypt(unsigned char* plaintext, unsigned char* ciphertext);
		Cipher(unsigned char* key);

	private:
		enum cipherType {aes1, aes2, des3} cipher;
		const EVP_CIPHER* aes128 = EVP_aes_128_cbc();
		const EVP_CIPHER* aes256 = EVP_aes_256_cbc();
		const EVP_CIPHER* tripledes = EVP_des_ede3_cbc();

		unsigned char *cipherkey;

		const int aes128KeySize = 16;
		const int aes256KeySize = 32;
		const int aesBlockSize = 16;
		const int aesIVSize = 16;

		const int desKeySize = 24;
		const int desBlockSize = 8;

		void handleErrors(void);
		int encryptStuff(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext);
		int decryptStuff(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext);
};

#endif /* CIPHER_H */