#ifndef KEYGEN_H
#define KEYGEN_H

#include <string>

using namespace std;

class Keygen {
	public:
		static int getMasterKey(char pwd[], size_t keysize, unsigned char* key);
		static int getHMACKey(char masterKey[], size_t keysize, unsigned char* key);
		static int getEncryptKey(char masterKey[], size_t keysize, unsigned char* key);

	private:
		static int getKey(char pwd[], unsigned char salt[], size_t keysize, int iter, unsigned char* key);
};

#endif /* KEYGEN_H */