#include <iostream>
#include <string>
#include <cstring>
#include <openssl/evp.h>
#include <keygen.h>
#include <cipher.h>

#define MASTER_KEY_LEN  32

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

	unsigned char* key = new unsigned char[MASTER_KEY_LEN];
	
	status = Keygen::getMasterKey(pwd, MASTER_KEY_LEN, shaver, key);
	char* test = (char*)malloc(MASTER_KEY_LEN);
	memcpy(test, key, MASTER_KEY_LEN);
	cout << "converted out: ";
	for(i=0; i<MASTER_KEY_LEN; i++) {
		printf("%x", test[i]&0xFF);
	}
	cout << endl;

	/* ===== GETTING HMAC KEY ===== */
	unsigned char* hmacKey = new unsigned char[KEY_SIZE];
	status = Keygen::getHMACKey(test, KEY_SIZE, shaver, hmacKey);
	cout << "hmac key: ";
	for(i=0; i<KEY_SIZE; i++) {
		cout << hex << int(hmacKey[i]);
	}
	cout << endl;

	/* ===== GETTING CIPHER KEY ===== */
	unsigned char* cipherKey = new unsigned char[KEY_SIZE];
	status = Keygen::getEncryptKey(test, KEY_SIZE, shaver, cipherKey);
	cout << "cipher key: ";
	for(i=0; i<KEY_SIZE; i++) {
		cout << hex << int(cipherKey[i]);
	}
	cout << endl;

	/* ===== ENCRYPTING ===== */
	string mytext;
	cout << "what to encrypt? ";
	cin.ignore();
	getline(cin, mytext);

	unsigned char *plaintext = new unsigned char[mytext.length() + 1];
	strcpy( (char* )plaintext, mytext.c_str());

	// TODO: vary block size based on cipher chosen
	// plaintext_size + (block_size - plaintext_size % block_size)
	// n + 8 - (n % 8)
	int ciphertext_len = (strlen((char*)plaintext) + BLOCK_SIZE) - (strlen((char*)plaintext)%BLOCK_SIZE);
	unsigned char *ciphertext = new unsigned char[ciphertext_len];

	// TODO: support multiple ciphers
	Cipher cipher(cipherKey, encalgo);
	int actualCipherLength = cipher.encrypt(plaintext, ciphertext, ciphertext_len);
	cout << "cipher text is: " << endl;
	BIO_dump_fp (stdout, (const char *)ciphertext, actualCipherLength);
	cout << endl;

	/* ==== DECRYPTING ===== */
	unsigned char *result = new unsigned char[strlen((char*)plaintext)+1];
	unsigned char *resultk = new unsigned char[strlen((char*)plaintext)];

	// 3des different block size wtf???
	int actualPlainLength = cipher.decrypt(result, ciphertext, actualCipherLength);
	cout << "decrypted text is: " << result << endl;

	delete[] key;
	delete[] hmacKey;
	delete[] cipherKey;

	delete[] plaintext;
	delete[] ciphertext;
	delete[] result;

    return 0;
}