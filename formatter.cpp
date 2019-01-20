#include <formatter.h>
#include <string>
#include <cstring>
#include <iostream>
#include <sstream>
#include <cstdlib>
#include <openssl/evp.h>
#include <math.h>

using namespace std;

//https://nachtimwald.com/2017/11/18/base64-encode-and-decode-in-c/
size_t b64_decoded_size(const char *in)
{
	size_t len;
	size_t ret;
	size_t i;

	if (in == NULL)
		return 0;

	len = strlen(in);
	ret = len / 4 * 3;

	for (i=len; i-->0; ) {
		if (in[i] == '=') {
			ret--;
		} else {
			break;
		}
	}

	return ret;
}

string Formatter::getFormattedData(string hash, string encalgo,
						int hmacLen, int cipherLen, int ivLen,
						unsigned char* hmac, unsigned char* ciphertext, unsigned char* iv) {

	int size = 0;

	// Get b64encoding of hmac in string
	size = 4*ceil(((double)hmacLen/3));
	unsigned char *strhmac = new unsigned char[size];
	int hmacSize = EVP_EncodeBlock(strhmac, hmac, hmacLen);
	if(hmacSize == -1) {
		cout << "ERROR ENCODING HMAC. " << endl;
	}

	size = 4*ceil(((double)ivLen/3));
	unsigned char *striv = new unsigned char[size];
	int ivSize = EVP_EncodeBlock(striv, iv, ivLen);
	if(ivSize == -1) {
		cout << "ERROR ENCODING IV. " << endl;
	}

	size = 4*ceil(((double)cipherLen/3));
	unsigned char *strcipher = new unsigned char[size];
	int cipherSize = EVP_EncodeBlock(strcipher, ciphertext, cipherLen);
	if(cipherSize == -1) {
		cout << "ERROR ENCODING CIPHER. " << endl;
	}

	stringstream ss;
	ss << hash << ";" << encalgo << ";" << hmacSize << ";" << ivSize << ";" << cipherSize << ";" << strhmac << ";" << striv << ";" << strcipher << ";" << cipherLen;
	string formattedString = ss.str();

	return formattedString;
}

int Formatter::parseFormattedData(string data,
					string& hashver, string& encalgo,
					unsigned char* hmac, unsigned char* iv, unsigned char* cipher, 
					string& cipherLen) {
	stringstream ss(data);
	string s;

	int decodeSize = 0;
	int blockSize = 0;

	string hmacSize, ivSize, cipherSize;
	string temp;

	//get hash type
	getline(ss, hashver, ';');

	//get enc algo type
	getline(ss, encalgo, ';');

	//get enc algo type
	getline(ss, hmacSize, ';');

	//get enc algo type
	getline(ss, ivSize, ';');

	//get enc algo type
	getline(ss, cipherSize, ';');

	//get hmac
	getline(ss, temp, ';');
	unsigned char *strhmac = new unsigned char[stoi(hmacSize)];
	blockSize = EVP_DecodeBlock(strhmac, (unsigned char*)temp.c_str(), stoi(hmacSize));
	if(blockSize == -1) {
		cout << "ERROR DECODING HMAC. " << endl;
	}
	memcpy(hmac, strhmac, stoi(hmacSize));

	//get iv
	getline(ss, temp, ';');
	unsigned char *striv = new unsigned char[stoi(ivSize)];
	blockSize = EVP_DecodeBlock(striv, (unsigned char*)temp.c_str(), stoi(ivSize));
	if(blockSize == -1) {
		cout << "ERROR DECODING IV. " << endl;
	}
	memcpy(iv, striv, stoi(ivSize));

	//get cipher
	getline(ss, temp, ';');
	unsigned char *strcipher = new unsigned char[stoi(cipherSize)];
	blockSize = EVP_DecodeBlock(strcipher, (unsigned char*)temp.c_str(), stoi(cipherSize));
	if(blockSize == -1) {
		cout << "ERROR DECODING CIPHER. " << endl;
	}
	memcpy(cipher, strcipher, stoi(cipherSize));

	//get cipherlen
	getline(ss, cipherLen, ';');
	
	return 0;
}