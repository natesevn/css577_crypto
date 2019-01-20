#include <iostream>
#include <string>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <keygen.h>
#include <cipher.h>
#include <formatter.h>

#define MASTER_KEY_LEN  32
#define HMAC_SIZE 32

using namespace std;

int main()
{
	size_t i;
	int status;

	string mypass;
	cout << "pass: ";
	cin >> mypass;
	char *pwd = &mypass[0];

	// sha256 or sha512 for pbkdf?
	string shaver;
	cout << "which sha for pbkdf: ";
	cin >> shaver;

	if(shaver == "sha256") {
		cout << "using sha 256" << endl;
	} else if(shaver == "sha512") {
		cout << "using sha 512" << endl;
	} else {
		cout << "invalid option" << endl;
		exit(EXIT_FAILURE);
	}

	// encryption method?
	int KEY_SIZE = 0;
	int BLOCK_SIZE = 0;
	int IV_SIZE = 0;
	string encalgo;
	cout << "which enc algo: ";
	cin >> encalgo;
	if(encalgo == "aes128") {
		cout << "using aes128" << endl;
		KEY_SIZE = Cipher::aes128KeySize;
		BLOCK_SIZE = Cipher::aesBlockSize;
		IV_SIZE = Cipher::aesIVSize;
	} else if(encalgo == "aes256") {
		cout << "using aes256" << endl;
		KEY_SIZE = Cipher::aes256KeySize;
		BLOCK_SIZE = Cipher::aesBlockSize;
		IV_SIZE = Cipher::aesIVSize;
	} else if(encalgo == "3des") {
		cout << "using 3des" << endl;
		KEY_SIZE = Cipher::desKeySize;
		BLOCK_SIZE = Cipher::desBlockSize;
		IV_SIZE = Cipher::desIVSize;
	} else {
		cout << "invalid option" << endl;
		exit(EXIT_FAILURE);
	}

	/* ===== GETTING MASTER KEY ===== */
	unsigned char* key = new unsigned char[MASTER_KEY_LEN];
	status = Keygen::getMasterKey(pwd, MASTER_KEY_LEN, shaver, key);
	char* masterKey = new char[MASTER_KEY_LEN+1];
	memcpy(masterKey, key, MASTER_KEY_LEN);
	cout << "converted out: ";
	for(i=0; i<MASTER_KEY_LEN; i++) {
		printf("%x", masterKey[i]&0xFF);
	}
	masterKey[MASTER_KEY_LEN] = '\0';
	cout << endl;

	/* ===== GETTING HMAC KEY ===== */
	unsigned char* hmacKey = new unsigned char[MASTER_KEY_LEN];
	status = Keygen::getHMACKey(masterKey, MASTER_KEY_LEN, shaver, hmacKey);
	cout << "hmac key: ";
	for(i=0; i<MASTER_KEY_LEN; i++) {
		cout << hex << int(hmacKey[i]);
	}
	cout << endl;

	/* ===== GETTING CIPHER KEY ===== */
	unsigned char* cipherKey = new unsigned char[KEY_SIZE];
	status = Keygen::getEncryptKey(masterKey, KEY_SIZE, shaver, cipherKey);
	cout << "cipher key: ";
	for(i=0; i<KEY_SIZE; i++) {
		cout << hex << int(cipherKey[i]);
	}
	cout << endl;

	/* ===== GETTING DATA TO ENCRYPT ===== */
	string mytext;
	cout << "what to encrypt? ";
	cin.ignore();
	getline(cin, mytext);

	unsigned char *plaintext = new unsigned char[mytext.length() + 1];
	strcpy( (char* )plaintext, mytext.c_str());

	/* ===== PREPARING CIPHER OBJECT ===== */
	unsigned char *iv = new unsigned char[IV_SIZE];
	if (!RAND_bytes(iv, IV_SIZE)) {
    	/* OpenSSL reports a failure, act accordingly */
		cout << "Error generating IV for encryption" << endl;
		exit(EXIT_FAILURE);
	}
	cout << "iv is: " << endl;
	BIO_dump_fp (stdout, (const char *)iv, IV_SIZE);
	cout << endl;

	Cipher cipher(cipherKey, hmacKey, iv, encalgo);

	/* ===== ENCRYPTING ===== */
	// cipher len =  n + 8 - (n % 8)
	int ciphertext_len = (strlen((char*)plaintext) + BLOCK_SIZE) - (strlen((char*)plaintext)%BLOCK_SIZE);
	unsigned char *ciphertext = new unsigned char[ciphertext_len];

	int actualCipherLength = cipher.encrypt(plaintext, ciphertext, ciphertext_len);
	cout << "cipher text is: " << endl;
	BIO_dump_fp (stdout, (const char *)ciphertext, actualCipherLength);
	cout << endl;

	/* ===== DECRYPTING ===== */
	unsigned char *result = new unsigned char[strlen((char*)plaintext)+1];

	int actualPlainLength = cipher.decrypt(result, ciphertext, actualCipherLength);
	result[actualPlainLength] = '\0';
	cout << "decrypted text is: " << result << endl;

	/* ===== GET HMAC ===== */
	unsigned char *hmac = new unsigned char[HMAC_SIZE];
	int hmacLen = cipher.getHmac(ciphertext, actualCipherLength, hmac);
	cout << "hmac is: " << endl;
	BIO_dump_fp (stdout, (const char *)hmac, hmacLen);
	cout << endl;

	/* ===== GET FORMATTED STRING ===== */
	string formattedString = Formatter::getFormattedData(shaver, encalgo, hmacLen, actualCipherLength, IV_SIZE,
		hmac, ciphertext, iv);
	cout << "formatted string is: " << formattedString << endl;

	/* ===== PARSE FORMATTED STRING ===== */
	string test1;
	string test2;
	unsigned char* test3 = new unsigned char[hmacLen+2];
	unsigned char* test4 = new unsigned char[IV_SIZE+2];
	unsigned char* test5 = new unsigned char[actualCipherLength+2];
	string test6;
	int test = Formatter::parseFormattedData(formattedString, test1, test2, test3, test4, test5, test6);

	cout << "decoded hmac is: " << endl;
	BIO_dump_fp (stdout, (const char*)test3, hmacLen);
	cout << "decoded iv is: " << endl;
	BIO_dump_fp (stdout, (const char*)test4, IV_SIZE);
	cout << "decoded cipher is: " << endl;
	BIO_dump_fp (stdout, (const char*)test5, stoi(test6));

	delete[] key;
	delete[] masterKey;
	delete[] hmacKey;
	delete[] cipherKey;

	delete[] iv;
	delete[] plaintext;
	delete[] ciphertext;
	delete[] result;
	delete[] hmac;

	delete[] test3;
	delete[] test4;
	delete[] test5;

    return 0;
}