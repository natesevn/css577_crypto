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

int getKeys(char* pwd, string shaver, int KEY_SIZE, unsigned char* masterKey, unsigned char* hmacKey, unsigned char* cipherKey) {
	int status;
	
	/* ===== GETTING MASTER KEY ===== */
	unsigned char* key = new unsigned char[MASTER_KEY_LEN];
	status = Keygen::getMasterKey(pwd, MASTER_KEY_LEN, shaver, key);
	char* thisKey = new char[MASTER_KEY_LEN+1]();
	memcpy(thisKey, key, MASTER_KEY_LEN);

	/* ===== GETTING HMAC KEY ===== */
	status = Keygen::getHMACKey(thisKey, MASTER_KEY_LEN, shaver, hmacKey);

	/* ===== GETTING CIPHER KEY ===== */
	status = Keygen::getEncryptKey(thisKey, KEY_SIZE, shaver, cipherKey);

	memcpy(masterKey, thisKey, MASTER_KEY_LEN);

	delete[] key;
	delete[] thisKey;

	return 0;
}

string getHashType(string hashver) {
	if(hashver == "sha256") {
	} else if(hashver == "sha512") {
	} else {
		cout << "invalid option" << endl;
		exit(EXIT_FAILURE);
	}

	return hashver;
}

string getCipherType(string encalgo, int* KEY_SIZE, int* BLOCK_SIZE, int* IV_SIZE) {
	if(encalgo == "aes128") {
		*KEY_SIZE = Cipher::aes128KeySize;
		*BLOCK_SIZE = Cipher::aesBlockSize;
		*IV_SIZE = Cipher::aesIVSize;
	} else if(encalgo == "aes256") {
		*KEY_SIZE = Cipher::aes256KeySize;
		*BLOCK_SIZE = Cipher::aesBlockSize;
		*IV_SIZE = Cipher::aesIVSize;
	} else if(encalgo == "3des") {
		*KEY_SIZE = Cipher::desKeySize;
		*BLOCK_SIZE = Cipher::desBlockSize;
		*IV_SIZE = Cipher::desIVSize;
	} else {
		cout << "invalid option" << endl;
		exit(EXIT_FAILURE);
	}

	return encalgo;
}

void getUserParams(string* password, int* KEY_SIZE, int* BLOCK_SIZE, int* IV_SIZE, string* hashver, string* cipher) {
	string mypass;
	cout << "pass: ";
	cin >> mypass;
	*password = mypass;

	// sha256 or sha512 for pbkdf?
	string shaver;
	cout << "which sha for pbkdf: ";
	cin >> shaver;
	*hashver = getHashType(shaver);

	// encryption method?
	string encalgo;
	cout << "which cipher: ";
	cin >> encalgo;
	*cipher = getCipherType(encalgo, KEY_SIZE, BLOCK_SIZE, IV_SIZE);

	return;
}

string encryptData() {
	// Get user params
	string password, shaver, encalgo;
	int KEY_SIZE = 0;
	int BLOCK_SIZE = 0;
	int IV_SIZE = 0;
	getUserParams(&password, &KEY_SIZE, &BLOCK_SIZE, &IV_SIZE, &shaver, &encalgo);
	char *pwd = &password[0];

	// Get required keys
	unsigned char* masterKey = new unsigned char[MASTER_KEY_LEN];
	unsigned char* hmacKey = new unsigned char[MASTER_KEY_LEN];
	unsigned char* cipherKey = new unsigned char[KEY_SIZE];
	getKeys(pwd, shaver, KEY_SIZE, masterKey, hmacKey, cipherKey);

	// String to encrypt
	string mytext;
	cout << "what to encrypt? ";
	cin.ignore();
	getline(cin, mytext);
	unsigned char *plaintext = new unsigned char[mytext.length() + 1];
	strcpy( (char* )plaintext, mytext.c_str());

	// Generate random IV
	unsigned char *iv = new unsigned char[IV_SIZE];
	if (!RAND_bytes(iv, IV_SIZE)) {
    	/* OpenSSL reports a failure, act accordingly */
		cout << "Error generating IV for encryption" << endl;
		exit(EXIT_FAILURE);
	}
	/*cout << "iv is: " << endl;
	BIO_dump_fp (stdout, (const char *)iv, IV_SIZE);
	cout << endl;*/

	// Create cipher object
	Cipher cipher(cipherKey, hmacKey, iv, encalgo);

	// Create ciphertext from plaintext
	int ciphertext_len = (strlen((char*)plaintext) + BLOCK_SIZE) - (strlen((char*)plaintext)%BLOCK_SIZE);
	unsigned char *ciphertext = new unsigned char[ciphertext_len];
	int actualCipherLength = cipher.encrypt(plaintext, ciphertext, ciphertext_len);
	/*cout << "cipher text is: " << endl;
	BIO_dump_fp (stdout, (const char *)ciphertext, actualCipherLength);
	cout << endl;*/

	// Create HMAC of IV+cipher
	unsigned char *hmac = new unsigned char[HMAC_SIZE];
	int hmacLen = cipher.getHmac(ciphertext, actualCipherLength, hmac);
	/*cout << "hmac is: " << endl;
	BIO_dump_fp (stdout, (const char *)hmac, hmacLen);
	cout << endl;*/

	// Get formatted string
	string formattedString = Formatter::getFormattedData(shaver, encalgo, hmacLen, actualCipherLength, IV_SIZE,
		hmac, ciphertext, iv);

	delete[] masterKey;
	delete[] hmacKey; 
	delete[] cipherKey;
	delete[] plaintext;
	delete[] iv;
	delete[] ciphertext;
	delete[] hmac;

	return formattedString;
}

string decryptData(string formattedString) {
	int ivLen = 0;
	int cipherLen = 0;

	// Get ivLen and cipherLen for allocating buffers
	Formatter::getFormattedDataSizes(formattedString, &ivLen, &cipherLen);

	// Get parameters from formatted string
	string hashver;
	string cipher;
	unsigned char* hmac = new unsigned char[HMAC_SIZE+2];
	unsigned char* iv = new unsigned char[ivLen+2];
	unsigned char* ciphertext = new unsigned char[cipherLen+2];
	string cipherSize;
	int test = Formatter::parseFormattedData(formattedString, hashver, cipher, hmac, iv, ciphertext, cipherSize);

	// Get parameters from hashtype and ciphertype
	int KEY_SIZE = 0;
	int BLOCK_SIZE = 0;
	int IV_SIZE = 0;
	string shaver = getHashType(hashver);
	string encalgo = getCipherType(cipher, &KEY_SIZE, &BLOCK_SIZE, &IV_SIZE);

	// Get password
	string mypass;
	cout << "pass: ";
	cin >> mypass;
	char *pwd = &mypass[0];

	// Get required keys
	unsigned char* masterKey = new unsigned char[MASTER_KEY_LEN];
	unsigned char* hmacKey = new unsigned char[HMAC_SIZE];
	unsigned char* cipherKey = new unsigned char[KEY_SIZE];
	getKeys(pwd, shaver, KEY_SIZE, masterKey, hmacKey, cipherKey);

	// Get cipher object and decrypt
	Cipher newcipher(cipherKey, hmacKey, iv, encalgo);
	unsigned char *text = new unsigned char[stoi(cipherSize)];
	int status = newcipher.decrypt(text, ciphertext, stoi(cipherSize));

	string result(reinterpret_cast<char*>(text));

	delete[] hmac;
	delete[] iv;
	delete[] ciphertext;
	delete[] masterKey;
	delete[] hmacKey;
	delete[] cipherKey;
	delete[] text;

	return result;
}

int main()
{
	//encrypt or decrypt data?
	string choice, result;
	cout << "encrypt or decrypt: ";
	cin >> choice;

	if(choice == "encrypt") {
		result = encryptData();
	} else if(choice == "decrypt") {
		string data;
		cout << "enter formatted data: ";
		cin >> data;
		result = decryptData(data);
	} else {
		cout << "invalid option" << endl;
		exit(EXIT_FAILURE);
	}

	cout << result << endl;

    return 0;
}