#include <keygen.h>
#include <string>
#include <cstring>
#include <openssl/evp.h>
#include <iostream>

#define KEY_LEN      32
#define KEK_KEY_LEN  32
#define ITERATION     1

using namespace std;

int Keygen::getKey(char pwd[], unsigned char salt[], size_t keysize, int iter, unsigned char* key) {

	size_t i;
	unsigned char *out = new unsigned char[keysize];

	// can change this to EVP_sha256(), EVP_sha512()
	const EVP_MD* sha256 = EVP_sha1();
	
	// use pbkdf2 to get key
    if( PKCS5_PBKDF2_HMAC(pwd, strlen(pwd), salt, strlen((char*)salt), iter, sha256, keysize, out) != 0 )
    {
		memcpy(key, out, keysize);
		delete[] out;
		return 0;
    }
    else
    {
        fprintf(stderr, "PKCS5_PBKDF2_HMAC_SHA1 failed\n");
		delete[] out;
		return -1;
    }

	return 0;
}

int Keygen::getMasterKey(char pwd[], size_t keysize, unsigned char* key) {
	// buffer to hold the master key and salt values
    unsigned char *out = new unsigned char[keysize]; 
    unsigned char salt_value[] = {'s','a','l','t'};

	int result = 0;
	// get master key
	result = getKey(pwd, salt_value, keysize, ITERATION, out);

	// copy master key to passed in char array
	memcpy(key, out, keysize);
	delete[] out;

	return 0;
}

int Keygen::getHMACKey(char masterKey[], size_t keysize, unsigned char* key) {
	// buffer to hold the master key and salt values
    unsigned char *out = new unsigned char[keysize]; 
    unsigned char salt_value[] = {'h','m','a','c'};

	int result = 0;
	// get master key
	result = getKey(masterKey, salt_value, keysize, 1, out);

	// copy hmac key to passed in char array
	memcpy(key, out, keysize);
	delete[] out;

	return 0;
}

int Keygen::getEncryptKey(char masterKey[], size_t keysize, unsigned char* key) {
	// buffer to hold the master key and salt values
    unsigned char *out = new unsigned char[keysize]; 
    unsigned char salt_value[] = {'c','i','p','h','e','r'};

	int result = 0;
	// get master key
	result = getKey(masterKey, salt_value, keysize, 1, out);

	// copy hmac key to passed in char array
	memcpy(key, out, keysize);
	delete[] out;

	return 0;
}

