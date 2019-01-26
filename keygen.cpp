#include <keygen.h>
#include <string>
#include <cstring>
#include <openssl/evp.h>
#include <iostream>

#define ITERATION 100000

using namespace std;

int Keygen::getKey(char pwd[], unsigned char salt[], size_t keysize, int iter, string shaver, unsigned char* key) {
	size_t i;
	// Buffer to hold resulting key
	unsigned char *out = new unsigned char[keysize];

	// Object holding hash algorithm
	const EVP_MD* sha = EVP_sha1();
	if(shaver == "sha256") {
		sha = EVP_sha256();
	} else if(shaver == "sha512") {
		sha = EVP_sha512();
	}
	
	// Get key using PBKDF2
	int status = 0;
	status = PKCS5_PBKDF2_HMAC(pwd, strlen(pwd), salt, strlen((char*)salt), iter, sha, keysize, out);
    if( status != 0 )
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

	return status;
}

int Keygen::getMasterKey(char pwd[], size_t keysize, string shaver, unsigned char* key, unsigned char* masterSalt) {
	// Buffer to hold the master key and salt
    unsigned char *out = new unsigned char[keysize]; 

	int result = 0;

	// Get master key
	result = getKey(pwd, masterSalt, keysize, ITERATION, shaver, out);

	// Copy master key to passed in key buffer
	memcpy(key, out, keysize);
	delete[] out;

	return result;
}

int Keygen::getHMACKey(char masterKey[], size_t keysize, string shaver, unsigned char* key) {
	// Buffer to hold the hmac key and salt value
    unsigned char *out = new unsigned char[keysize]; 
    unsigned char salt_value[] = {'h','m','a','c'};

	int result = 0;
	// Get hmac key
	result = getKey(masterKey, salt_value, keysize, 1, shaver, out);

	// Copy hmac key to passed in buffer
	memcpy(key, out, keysize);
	delete[] out;

	return result;
}

int Keygen::getEncryptKey(char masterKey[], size_t keysize, string shaver, unsigned char* key) {
	// Buffer to hold the master key and salt
    unsigned char *out = new unsigned char[keysize]; 
    unsigned char salt_value[] = {'c','i','p','h','e','r'};

	int result = 0;
	// Get cipher key
	result = getKey(masterKey, salt_value, keysize, 1, shaver, out);

	// Copy cipher key to passed in buffer
	memcpy(key, out, keysize);
	delete[] out;

	return result;
}

