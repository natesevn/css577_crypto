#ifndef KEYGEN_H
#define KEYGEN_H

#include <string>

using namespace std;

class Keygen {
	public:
		/* 
		 * Helper function to get master key based on parameters
		 * @pwd: password from which master key will be derived
		 * @keysize: desired size of master key
		 * @shaver: hash algorithm to use
		 * @key: buffer for resulting master key
		 */
		static int getMasterKey(char pwd[], size_t keysize, string shaver, unsigned char* key);

		/* 
		 *  Helper function to get HMAC key based on parameters
		 * @masterKey: master key from which HMAC key will be derived
		 * @keysize: desired size of HMAC key
		 * @shaver: hash algorithm to use
		 * @key: buffer for resulting HMAC key
		 */
		static int getHMACKey(char masterKey[], size_t keysize, string shaver, unsigned char* key);

		/* 
		 * Helper function to get cipher key based on parameters
		 * @masterKey: master key from which cipher key will be derived
		 * @keysize: desired size of cipher key
		 * @shaver: hash algorithm to use
		 * @key: buffer for resulting cipher key
		 */
		static int getEncryptKey(char masterKey[], size_t keysize, string shaver, unsigned char* key);

	private:
		/*
		 * Derive a key using PBKDF2 with specified parameters
		 * @pwd: character array from which key will be derived
		 * @salt: salt for PBKDF2
		 * @keysize: desired keysize
		 * @iter: desired number of iterations
		 * @shaver: desired hash algo
		 * @key: buffer for resulting key
		 */
		static int getKey(char pwd[], unsigned char salt[], size_t keysize, int iter, string shaver, unsigned char* key);
};

#endif /* KEYGEN_H */