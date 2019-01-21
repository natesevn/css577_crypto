#ifndef CIPHER_H
#define CIPHER_H

#include <string>
#include <openssl/evp.h>

using namespace std;

class Cipher {
	public:

		/* Constructor; initializes class fields based on parameters
		 * Returns cipher object on success
		 * @ckey: cipher key to use
		 * @hkey: hmac key to use
		 * @iv: iv to use
		 * @encalgo: cipher algorithm to use
		 */
		Cipher(unsigned char* ckey, unsigned char* hkey, unsigned char* iv, string encalgo);

		/*
		 * Helper function to encrypt plaintext
		 * Returns actual size of ciphertext on success
		 * @plaintext: plaintext to be encrypted
		 * @ciphertext: buffer for resulting ciphertext
		 * @expectedLen: expected length of ciphertext based on plaintext
		 */
		int encrypt(unsigned char* plaintext, unsigned char* ciphertext, int expectedLen);

		/*
		 * Helper function to decrypt ciphertext
		 * Returns size of plaintext on success
		 * @plaintext: buffer for resulting plaintext
		 * @ciphertext: ciphertext to be decrypted
		 * @ciphertextLen: length of ciphertext
		 */
		int decrypt(unsigned char* plaintext, unsigned char* ciphertext, int ciphertextLen);

		/*
		 * Get HMAC of ciphertext + IV
		 * Returns size of HMAC on success
		 * @ciphertext: ciphertext to be hmac'd
		 * @ciphertextLen: length of ciphertext
		 * @hmac: buffer for resulting hmac
		 */
		int getHmac(unsigned char* ciphertext, int ciphertextLen, unsigned char* hmac);

		/*
		 * Check if passed in HMAC matches calculated HMAC
		 * Returns True if they match, False otherwise
		 * @ciphertext: ciphertext for HMAC
		 * @ciphertextLen: length of ciphertext
		 * @hash: HMAC hash to compare it to
		 */
		bool verifyHmac(unsigned char* ciphertext, int ciphertextLen, unsigned char* hash);

		// Constants for parameters of various cipher types
		static const int aes128KeySize = 16;
		static const int aes256KeySize = 32;
		static const int aesBlockSize = 16;
		static const int aesIVSize = 16;

		static const int desKeySize = 24;
		static const int desBlockSize = 8;
		static const int desIVSize = 8;

		static const int hmacSize = 32;

	private:

		// CLass fields to store keys and iv
		unsigned char *cipherkey;
		unsigned char *hmackey;
		unsigned char *cipheriv;

		// Class fields to store cipher parameters
		int keySize;
		int blockSize;
		int ivSize; 
		
		// Class field to store cipher type
		const EVP_CIPHER* algotype;

		// Error handler; prints an error and exits program
		void handleErrors(int status);
		
		/*
		 * Encrypts plaintext
		 * @plaintext: plaintext to be encrypted
		 * @plaintext_len: plaintext length
		 * @key: cipher key to use
		 * @iv: iv to use
		 * @algo; cipher type to use
		 * @ciphertext: buffer for resulting ciphertext
		 */
		int encryptStuff(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, const EVP_CIPHER* algo, unsigned char *ciphertext);

  		/*
		 * Decrypts ciphertext
		 * @ciphertext: cipher to decrypt
		 * @ciphertext_len: length of ciphertext
		 * @key: cipher key to use
		 * @iv: iv to use
		 * @algo; cipher type to use
		 * @plaintext: buffer for resulting plaintext
		 */
		int decryptStuff(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, const EVP_CIPHER* algo, unsigned char *plaintext);
};

#endif /* CIPHER_H */