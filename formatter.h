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

		static void getFormattedDataSizes(string data, int* ivLen, int* cipherLen);
		static int parseFormattedData(string formattedData,
				string& hashver, string& encalgo,
				unsigned char* hmac, unsigned char* cipher, unsigned char* iv, 
				string& cipherLen);

};

#endif /* FORMATTER_H */