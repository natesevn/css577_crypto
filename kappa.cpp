#include <iostream>
#include <string>
#include <cstring>
#include <openssl/evp.h>
#include <keygen.h>
#include <cipher.h>

#define KEY_LEN      32
#define KEK_KEY_LEN  32
#define ITERATION     1 


using namespace std;

int main()
{
	size_t i;
	int status;

	unsigned char* key = new unsigned char[KEK_KEY_LEN];

	string mypass;
	cout << "pass: ";
	cin >> mypass;
	char *pwd = &mypass[0];
	
	status = Keygen::getMasterKey(pwd, KEK_KEY_LEN, key);
	cout << "pre converted out: ";
	for(i=0; i<KEK_KEY_LEN; i++) {
		cout << hex << int(key[i]);
	}
	cout << endl;

	char* test = (char*)malloc(KEK_KEY_LEN);
	memcpy(test, key, KEK_KEY_LEN);
    //test = (char *) key;
	//char* test = reinterpret_cast<char*>(key);
	cout << "converted out: ";
	for(i=0; i<KEK_KEY_LEN; i++) {
		printf("%x", test[i]&0xFF);
	}
	cout << endl;

	/* ===== GETTING HMAC KEY ===== */
	unsigned char* hmacKey = new unsigned char[KEK_KEY_LEN];
	status = Keygen::getHMACKey(test, KEK_KEY_LEN, hmacKey);
	cout << "hmac key: ";
	for(i=0; i<KEK_KEY_LEN; i++) {
		cout << hex << int(hmacKey[i]);
	}
	cout << endl;

	/* ===== GETTING CIPHER KEY ===== */
	unsigned char* cipherKey = new unsigned char[KEK_KEY_LEN];
	status = Keygen::getEncryptKey(test, KEK_KEY_LEN, cipherKey);
	cout << "cipher key: ";
	for(i=0; i<KEK_KEY_LEN; i++) {
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
	int ciphertext_len = strlen((char*)plaintext) + (16 - (strlen((char*)plaintext)%16));
	unsigned char *ciphertext = new unsigned char[ciphertext_len];

	// TODO: support multiple ciphers
	Cipher cipher(cipherKey);
	cipher.encrypt(plaintext, ciphertext);
	cout << "cipher text is: ";
	BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);
	cout << endl;
	//cipher.decrypt();

	/* ==== DECRYPTING ===== */
	unsigned char *result = new unsigned char[strlen((char*)plaintext)];
	cipher.decrypt(result, ciphertext);
	cout << "decrypted text is: " << result << endl;


	delete[] key;
	delete[] hmacKey;
	delete[] cipherKey;

	delete[] plaintext;
	delete[] ciphertext;
	delete[] result;

    return 0;
}