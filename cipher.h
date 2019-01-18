#ifndef CIPHER_H
#define CIPHER_H

#include <string>
#include <openssl/evp.h>

using namespace std;

class Cipher {
	public:
		int encrypt(unsigned char* plaintext, unsigned char* ciphertext, int expectedLen);
		int decrypt(unsigned char* plaintext, unsigned char* ciphertext, int ciphertextLen);
		
		Cipher(unsigned char* key, string encalgo);

		static const int aes128KeySize = 16;
		static const int aes256KeySize = 32;
		static const int aesBlockSize = 16;
		static const int aesIVSize = 16;

		static const int desKeySize = 24;
		static const int desBlockSize = 8;
		static const int desIVSize = 8;

	private:
		unsigned char *cipherkey;
		const EVP_CIPHER* algotype;

		void handleErrors(void);
		int encryptStuff(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, const EVP_CIPHER* algo, unsigned char *ciphertext);
		int decryptStuff(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, const EVP_CIPHER* algo, unsigned char *plaintext);
};

#endif /* CIPHER_H */