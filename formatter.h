#ifndef FORMATTER_H
#define FORMATTER_H

#include <string>

using namespace std;

class Formatter {
	public:
		static string getFormattedData(
				string hash, string encalgo,
				int hmacLen, int cipherLen, int ivLen,
				unsigned char* hmac, unsigned char* ciphertext, unsigned char* iv);

};

#endif /* FORMATTER_H */