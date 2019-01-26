#ifndef FORMATTER_H
#define FORMATTER_H

#include <string>

using namespace std;

class Formatter {
	public:

		/*
		 * Get formatted string with metadata
		 * Returns b64 encoded data with metadata in the following format:
		 * hashtype || ciphertype || b64 hmac size || b64 iv size || b64 cipher size || original ciphertext length || hmac || iv || ciphertext;		
		 * Prints error message and exits program upon failure
		 * @hash: hash algo used
		 * @encalgo: cipher algo used
		 * @hmacLen: length of original hmac
		 * @cipherLen: length of original ciphertext
		 * @ivLen: length of original iV
		 * @hmac: hmac of cipher+iv
		 * @ciphertext: ciphertext
		 * @iv: iv
		 */
		static string getFormattedData(
				string hash, string encalgo,
				int saltLen, int hmacLen, int cipherLen, int ivLen,
				unsigned char* masterSalt, unsigned char* hmac, unsigned char* ciphertext, unsigned char* iv);

		/*
		 * Get b64 sizes of iv and cipher for buffer allocation
		 * @data: formatted string with meta data
		 * @ivLen: will hold b64 iv length
		 * @cipherLen: will hold b64 cipher length
		 */
		static void getFormattedDataSizes(string data, int* ivLen, int* cipherLen);

		/*
		 * Parse and decode b64 formatted string with metadata
		 * Prints error and exits progarm on failure
		 * @formattedData: formatted string
		 * @hashver: buffer for resulting hash algorithm used on success
		 * @encalgo: buffer for resulting cipher type used on success
		 * @hmac: buffer for resulting hmac on success
		 * @cipher: buffer for resulting cipher on success
		 * @iv: buffer for resulting iv on success
		 * @cipherLen: buffer for resulting cipherLength on success
		 */
		static int parseFormattedData(string formattedData,
				string& hashver, string& encalgo,
				unsigned char* masterSalt, unsigned char* hmac, unsigned char* cipher, unsigned char* iv, 
				string& cipherLen);

};

#endif /* FORMATTER_H */