#include <formatter.h>
#include <string>
#include <cstring>
#include <iostream>
#include <sstream>
#include <cstdlib>
#include <openssl/evp.h>
#include <math.h>

using namespace std;

string Formatter::getFormattedData(string hash, string encalgo,
						int saltLen, int hmacLen, int cipherLen, int ivLen,
						unsigned char* masterSalt, unsigned char* hmac, unsigned char* ciphertext, unsigned char* iv) {

	int size = 0;

	// Get b64encoding of masterSalt in string
	size = 4*ceil(((double)saltLen/3));
	unsigned char *strsalt = new unsigned char[size+1];
	int saltSize = EVP_EncodeBlock(strsalt, masterSalt, saltLen);
	if(saltSize == -1) {
		cout << "ERROR ENCODING SALT. " << endl;
		exit(EXIT_FAILURE);
	}

	// Get b64encoding of hmac in string
	size = 4*ceil(((double)hmacLen/3));
	unsigned char *strhmac = new unsigned char[size+1];
	int hmacSize = EVP_EncodeBlock(strhmac, hmac, hmacLen);
	if(hmacSize == -1) {
		cout << "ERROR ENCODING HMAC. " << endl;
		exit(EXIT_FAILURE);
	}

	// Get b64encoding of iv in string
	size = 4*ceil(((double)ivLen/3));
	unsigned char *striv = new unsigned char[size+1];
	int ivSize = EVP_EncodeBlock(striv, iv, ivLen);
	if(ivSize == -1) {
		cout << "ERROR ENCODING IV. " << endl;
		exit(EXIT_FAILURE);
	}

	// Get b64encoding of cipher in string
	size = 4*ceil(((double)cipherLen/3));
	unsigned char *strcipher = new unsigned char[size+1];
	int cipherSize = EVP_EncodeBlock(strcipher, ciphertext, cipherLen);
	if(cipherSize == -1) {
		cout << "ERROR ENCODING CIPHER. " << endl;
		exit(EXIT_FAILURE);
	}

	// Concatenate all relevant values
	stringstream ss;
	ss << hash << ";" << encalgo << ";" << saltSize << ";" << hmacSize << ";" << ivSize << ";" << cipherSize << ";" << cipherLen << ";" << strsalt << ";" << strhmac << ";" << striv << ";" << strcipher;
	string formattedString = ss.str();

	delete[] strsalt;
	delete[] strhmac;
	delete[] striv;
	delete[] strcipher;

	return formattedString;
}

void Formatter::getFormattedDataSizes(string data, int* ivLen, int* cipherLen) {
	stringstream ss(data);
	string temp;

	// Skip first 4 values
	getline(ss, temp, ';');
	getline(ss, temp, ';');
	getline(ss, temp, ';');
	getline(ss, temp, ';');

	// Get iv and cipher length
	string ivSize, cipherSize;
	getline(ss, ivSize, ';');
	getline(ss, cipherSize, ';');

	*ivLen = stoi(ivSize);
	*cipherLen = stoi(cipherSize);

	return;
}

int Formatter::parseFormattedData(string data,
					string& hashver, string& encalgo,
					unsigned char* masterSalt, unsigned char* hmac, unsigned char* iv, unsigned char* cipher, 
					string& cipherLen) {
	stringstream ss(data);
	string s;

	int decodeSize = 0;
	int blockSize = 0;

	string saltSize, hmacSize, ivSize, cipherSize;
	string temp;

	//get hash type
	getline(ss, hashver, ';');

	//get enc algo type
	getline(ss, encalgo, ';');
	
	//get b64 salt size
	getline(ss, saltSize, ';');

	//get b64 hmac sie
	getline(ss, hmacSize, ';');

	//get b64 ivSize
	getline(ss, ivSize, ';');

	//get b64 cipherSize
	getline(ss, cipherSize, ';');

	//get cipher length
	getline(ss, cipherLen, ';');

	//get salt and copy to passed in buffer
	getline(ss, temp, ';');
	unsigned char *strsalt = new unsigned char[stoi(saltSize)+1];
	blockSize = EVP_DecodeBlock(strsalt, (unsigned char*)temp.c_str(), stoi(saltSize));
	if(blockSize == -1) {
		cout << "ERROR DECODING SALT. " << endl;
	}
	memcpy(masterSalt, strsalt, blockSize);

	//get hmac and copy to passed in buffer
	getline(ss, temp, ';');
	unsigned char *strhmac = new unsigned char[stoi(hmacSize)+1];
	blockSize = EVP_DecodeBlock(strhmac, (unsigned char*)temp.c_str(), stoi(hmacSize));
	if(blockSize == -1) {
		cout << "ERROR DECODING HMAC. " << endl;
	}
	memcpy(hmac, strhmac, blockSize);

	//get iv and copy to passed in buffer
	getline(ss, temp, ';');
	unsigned char *striv = new unsigned char[stoi(ivSize)+1];
	blockSize = EVP_DecodeBlock(striv, (unsigned char*)temp.c_str(), stoi(ivSize));
	if(blockSize == -1) {
		cout << "ERROR DECODING IV. " << endl;
	}
	memcpy(iv, striv, blockSize);

	//get cipher and copy to passed in buffer
	getline(ss, temp, ';');
	unsigned char *strcipher = new unsigned char[stoi(cipherSize)+1];
	blockSize = EVP_DecodeBlock(strcipher, (unsigned char*)temp.c_str(), stoi(cipherSize));
	if(blockSize == -1) {
		cout << "ERROR DECODING CIPHER. " << endl;
	}
	memcpy(cipher, strcipher, blockSize);

	delete[] strhmac;
	delete[] striv;
	delete[] strcipher;
	
	return 0;
}