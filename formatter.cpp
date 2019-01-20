#include <formatter.h>
#include <string>
#include <cstring>
#include <iostream>
#include <sstream>
#include <openssl/evp.h>

using namespace std;

string Formatter::getFormattedData(string hash, string encalgo,
						int hmacLen, int cipherLen, int ivLen,
						unsigned char* hmac, unsigned char* ciphertext, unsigned char* iv) {

	stringstream hexhmac;
	for(int i=0; i<hmacLen; ++i)
    	hexhmac << hex << (int)hmac[i];
	string stringhmac = hexhmac.str();

	stringstream hexcipher;
	for(int i=0; i<cipherLen; ++i)
    	hexcipher << hex << (int)ciphertext[i];
	string stringcipher = hexcipher.str();

	stringstream hexiv;
	for(int i=0; i<ivLen; ++i)
    	hexiv << hex << (int)iv[i];
	string stringiv = hexiv.str();

	stringstream ss;
	ss << hash << "," << encalgo << ";" << stringhmac << ";" << stringiv << ";" << stringcipher;
	string formattedString = ss.str();

	return formattedString;
}