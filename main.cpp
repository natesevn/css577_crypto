#include <iostream>
#include <fstream>
#include <sstream> 
#include <string>
#include <cstring>
#include <openssl/rand.h>
#include <keygen.h>
#include <cipher.h>
#include <formatter.h>

#define MASTER_KEY_LEN  32
#define HMAC_SIZE 32

using namespace std;

/* 
 * Get master, hmac, and cipher keys
 * Returns 0 on success
 * Ends program with error message on failure
 * pwd: char array containing password
 * shaver: hash algorithm to use
 * KEY_SIZE: desired cipher key size
 * masterKey: will hold masterKey on return
 * hmacKey: will hold hmacKey on return
 * cipherKey: will hold cipherKey on return
 */
int getKeys(char* pwd, string shaver, int KEY_SIZE, unsigned char* masterKey, unsigned char* hmacKey, unsigned char* cipherKey) {
	int status;
	
	// Get master key
	unsigned char* key = new unsigned char[MASTER_KEY_LEN];
	status = Keygen::getMasterKey(pwd, MASTER_KEY_LEN, shaver, key);
	if(status == -1) {
		cout << "Failed to get master key." << endl;
		exit(EXIT_FAILURE);
	}

	// Convert master key to char* from unsigned char*, and copy it to new variable
	char* thisKey = new char[MASTER_KEY_LEN+1]();
	memcpy(thisKey, key, MASTER_KEY_LEN);

	// Get hmac key
	status = Keygen::getHMACKey(thisKey, MASTER_KEY_LEN, shaver, hmacKey);
	if(status == -1) {
		cout << "Failed to get HMAC key." << endl;
		exit(EXIT_FAILURE);
	}

	// Get cipher key
	status = Keygen::getEncryptKey(thisKey, KEY_SIZE, shaver, cipherKey);
	if(status == -1) {
		cout << "Failed to get cipher key." << endl;
		exit(EXIT_FAILURE);
	}

	memcpy(masterKey, thisKey, MASTER_KEY_LEN);

	delete[] key;
	delete[] thisKey;

	return status;
}

/* 
 * Check if hashtype is valid
 * Returns hash type on success
 * Ends program with error message on failure
 */
string getHashType(string hashver) {
	if(hashver == "sha256") {
	} else if(hashver == "sha512") {
	} else {
		cout << "invalid option" << endl;
		exit(EXIT_FAILURE);
	}

	return hashver;
}

/*
 * Check if encalgo is a valid cipher type, and assigns key, block, and iv size based on cipher type
 * Returns cipher type on success
 * Ends program with error message on failure
 * KEY_SIZE: will hold cipher key size on success
 * BLOCK_SIZE: will hold block size on success
 * IV_SIZE: will hold iv size on success
 */
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

/*
 * Gets parameters to create cipher object based on user input
 * password: holds entered password on success
 * KEY_SIZE: will hold cipher key size on success
 * BLOCK_SIZE: will hold block size on success
 * IV_SIZE: will hold iv size on success
 * hashver: will hold hash type on success
 * cipher: will hold cipher type on success
 */
void getUserParams(string* password, int* KEY_SIZE, int* BLOCK_SIZE, int* IV_SIZE, string* hashver, string* cipher) {
	// Get user password
	string mypass;
	cout << "Enter password: ";
	cin >> mypass;
	*password = mypass;

	// sha256 or sha512 for pbkdf?
	string shaver;
	cout << "SHA version for PBKDF (SHA256, SHA512): ";
	cin >> shaver;
	*hashver = getHashType(shaver);

	// encryption method?
	string encalgo;
	cout << "Cipher type (AES128, AES256, 3DES): ";
	cin >> encalgo;
	*cipher = getCipherType(encalgo, KEY_SIZE, BLOCK_SIZE, IV_SIZE);

	return;
}

/* 
 * Encrypt data based on parameters entered by user
 * Returns formatted string with metadata on success
 * Ends program with error message on failure
 */ 
string encryptData() {
	// Get user input parameters
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
	cout << "What to encrypt: ";
	cin.ignore();
	getline(cin, mytext);
	unsigned char *plaintext = new unsigned char[mytext.length() + 1];
	strcpy((char* )plaintext, mytext.c_str());

	// Generate random IV
	unsigned char *iv = new unsigned char[IV_SIZE];
	if (!RAND_bytes(iv, IV_SIZE)) {
		cout << "Error generating IV for encryption" << endl;
		exit(EXIT_FAILURE);
	}

	// Create cipher object
	Cipher cipher(cipherKey, hmacKey, iv, encalgo);

	// Encrypt plaintext
	// Use (n + block) - (n % block) to predict ciphertext length, where n = plaintext length and block = block size
	int ciphertext_len = (strlen((char*)plaintext) + BLOCK_SIZE) - (strlen((char*)plaintext) % BLOCK_SIZE);
	unsigned char *ciphertext = new unsigned char[ciphertext_len];
	int actualCipherLength = cipher.encrypt(plaintext, ciphertext, ciphertext_len);

	// Create HMAC of IV+cipher
	unsigned char *hmac = new unsigned char[HMAC_SIZE];
	int hmacLen = cipher.getHmac(ciphertext, actualCipherLength, hmac);

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

/*
 * Given formatted string with metadata, extract header information and decrypt cipher
 * Return decrypted plaintext on success
 */
string decryptData(string formattedString) {
	int ivLen = 0;
	int cipherLen = 0;

	// Get ivLen and cipherLen for allocating buffers for the next step
	Formatter::getFormattedDataSizes(formattedString, &ivLen, &cipherLen);

	// Break apart formatted string and extract metadata and ciphertext to allocated buffers
	string hashver;
	string cipher;
	unsigned char* hmac = new unsigned char[HMAC_SIZE+2];
	unsigned char* iv = new unsigned char[ivLen+2];
	unsigned char* ciphertext = new unsigned char[cipherLen+2];
	string cipherSize;
	int test = Formatter::parseFormattedData(formattedString, hashver, cipher, hmac, iv, ciphertext, cipherSize);

	// Get parameters from extracted hashtype and ciphertype
	int KEY_SIZE = 0;
	int BLOCK_SIZE = 0;
	int IV_SIZE = 0;
	string shaver = getHashType(hashver);
	string encalgo = getCipherType(cipher, &KEY_SIZE, &BLOCK_SIZE, &IV_SIZE);

	// Get user password
	string mypass;
	cout << "Password: ";
	cin >> mypass;
	char *pwd = &mypass[0];

	// Get required keys
	unsigned char* masterKey = new unsigned char[MASTER_KEY_LEN];
	unsigned char* hmacKey = new unsigned char[HMAC_SIZE];
	unsigned char* cipherKey = new unsigned char[KEY_SIZE];
	getKeys(pwd, shaver, KEY_SIZE, masterKey, hmacKey, cipherKey);

	// Create cipher object
	Cipher newcipher(cipherKey, hmacKey, iv, encalgo);

	// Check if hmac hash is corrupted
	bool correctHmac = false;
	correctHmac = newcipher.verifyHmac(ciphertext, stoi(cipherSize), hmac);
	if(!correctHmac) {
		cout << "HMAC values do not match." << endl;
		exit(EXIT_FAILURE);
	} else {
		cout << "HMAC value verified." << endl;
	}

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
	string choice, result;
	cout << "Encrypt or decrypt: ";
	cin >> choice;

	if(choice == "encrypt") {
		result = encryptData();

		string data;
		cout << "Enter filename to save results in: ";
		cin >> data;

		// Writing to file
		ofstream outfile(data);
		if(!outfile) {
			cout << "Can't open file." << endl;
			exit(1);
		}
		outfile << result << endl;
		outfile.close();

		cout << "Success." << endl;

	} else if(choice == "decrypt") {
		string data;
		cout << "Enter file name: ";
		cin >> data;

		// Reading from file
		ifstream infile(data);
		if(!infile) {
			cout << "Can't open file." << endl;
			exit(1);
		}
		stringstream buffer;
		buffer << infile.rdbuf();

		string formattedString = buffer.str();
		result = decryptData(formattedString);

		infile.close();

		cout << "Decrypted cipher: " << result << endl;

	} else {
		cout << "invalid option" << endl;
		exit(EXIT_FAILURE);
	}

    return 0;
}