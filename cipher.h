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
		enum cipherType {aes256, aes512, des3} cipher;
		const EVP_CIPHER* aes = EVP_aes_256_cbc();

		unsigned char *cipherkey;

		void handleErrors(void);
		int encryptStuff(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext);
		int decryptStuff(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext);
};

#endif /* CIPHER_H */