#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>

#include <stdio.h>
#include <stdlib.h>

using namespace std;

// InputString = 32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34
// Cipher Key = 2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c

// Prototypes.
// Convert String to Hex Array
unsigned int *cipherStringToHexaArray(const std::string &, int);
// Mở rộng khóa AES-128.
// ConsoleOutputFunc Word (dạng string).
void showWord(unsigned int);
// ConsoleOutputFunc Matrix (dạng string)
void showMatrix(unsigned int);
// ReturnOutputFunc.
string matrixToStr(unsigned int* word);
string wordToStr(unsigned int);
// Dịch vòng trái 1 Byte.
unsigned int rotWord(unsigned int);
// Mã hóa giá trị rotWord theo subWordArray.
unsigned int subWord(unsigned int);
unsigned int xorRcon(unsigned int, int);
// Hàm G.
unsigned int G(unsigned int, int);
// Hàm mở rộng khóa.
unsigned int *keyExpansion(unsigned int *);
// Mã hóa AES.
// 1. Thay thế byte:
// sử dụng một hộp S-box để thực hiện một sự thay thế byte cho byte của toàn khối.
unsigned int *SubBytes(unsigned int *);
// 2. Một hoán vị đơn giản.
unsigned int *ShiftRows(unsigned int *);
unsigned int multiply_double(unsigned int);
unsigned int multiply_triple(unsigned int);
unsigned int multiply_column(unsigned int);
// 3. Phép thay thế sử dụng các phép toán trên GF(2^8).
unsigned int *MixColumns(unsigned int *);
// 4. Phép Xor Bitwise của khối hiện tại với một phần của khóa mở rộng.
unsigned int *AddRoundKey(unsigned int *, unsigned int *);
// Mã hóa AES => (Output).
unsigned int *EncryptionAES(unsigned int *, unsigned int *);
// Giải mã AES.
unsigned int *InvShiftRows(unsigned int *);
unsigned int InvSubWord(unsigned int);
unsigned int *InvSubBytes(unsigned int *);
unsigned int multiply_9(unsigned int);
unsigned int multiply_B(unsigned int);
unsigned int multiply_D(unsigned int);
unsigned int multiply_E(unsigned int);
unsigned int InvMultiply_column(unsigned int);
unsigned int *InvMixColumns(unsigned int *);
unsigned int *DecryptionAES(unsigned int *, unsigned int *);

unsigned int *cipherStringToHexaArray(const std::string &str, int length)
{
	unsigned int *arrayString = new unsigned int[4];
	for (int i = 0, j = 0; i < str.length(); i += length, j++)
	{
		arrayString[j] = std::stoul(str.substr(i, length), nullptr, 16);
		// showWord(arrayString[j]);
		cout << " ";
	}
	return arrayString;
}

int main()
{
	string inputString = "", cipherKey = "";
	do
	{
		cout << "Enter a string to encode (The length of the input string in AES can be 128 bits, 192 bits, or 256 bits, which is equivalent to 16 bytes, 24 bytes, or 32 bytes; If the input string is not long enough, which is 16 bytes, the system will automatically add 0x00 to make up for it):" << endl;
		getline(cin, inputString);
		inputString.erase(remove(inputString.begin(), inputString.end(), ' '), inputString.end());
	} while (inputString.length() != 32);
	do
	{
		cout << "Enter the value of the security key (The length of the Cipher Key in AES can be 128 bits, 192 bits, or 256 bits, which is equivalent to 16 bytes, 24 bytes, or 32 bytes; If the security key is not long enough, which is 16 bytes, the system will automatically add 0x00 to make up for it):" << endl;
		getline(cin, cipherKey);
		cipherKey.erase(remove(cipherKey.begin(), cipherKey.end(), ' '), cipherKey.end());
		if (cipherKey.length() < 32) {
			int diff = 32 - cipherKey.length();
			string zeros(diff, '0');
			cipherKey += zeros;
		}
		cout << cipherKey << endl;
	} while (cipherKey.length() != 32);

	unsigned int *state = new unsigned int[4];
	unsigned int *key = new unsigned int[4];

	state = cipherStringToHexaArray(inputString, 2 * 4);
	key = cipherStringToHexaArray(cipherKey, 2 * 4);
	//	state[0] = 0x3243f6a8; state[1] = 0x885a308d; state[2] = 0x313198a2; state[3] = 0xe0370734;
	//	key[0] = 0x2B7E1516; key[1] = 0x28AED2A6; key[2] = 0xABF71588, key[3] = 0x09CF4F3C;

	unsigned int *Cipher = EncryptionAES(state, key);
	unsigned int *Decipher = DecryptionAES(Cipher, key);

	cout << endl;
	cout << "Encrypt String: " << matrixToStr(Cipher) << endl;
	cout << "Decrypt String: " << matrixToStr(Decipher) << endl;
}

// Print 1 Word 32-bit dạng String (trong mã hóa 128-bit).
string wordToStr(unsigned int word)
{
	string hexanString = "";
	for (int i = 1; i <= 8; i++)
	{
		std::ostringstream hexanChar;
		unsigned int hexan = (word >> (32 - i * 4)) & 0xF;
		hexanChar << std::hex << hexan;
		hexanString += hexanChar.str();
	}
	return hexanString;
}

void showWord(unsigned int word) {
	for (int i = 1; i <= 8; i++)
	{
		unsigned int hexan = (word >> (32 - i * 4)) & 0xF;
		printf("%X", hexan);
	}
}

// Dịch vòng trái 1 Byte.
unsigned int rotWord(unsigned int word)
{
	unsigned int byte_1 = (word >> 24) & 0xFF;
	unsigned int byte_234 = word & 0xFFFFFF;
	unsigned int rotWord = byte_1 | (byte_234 << 8);
	// cout << "rotWord("; showWord(word); cout << ") = "; showWord(rotWord);
	return rotWord;
}

// Mã hóa giá trị rotWord theo subWordArray.
unsigned int subWord(unsigned int rotWord)
{
	int subWordArray[] = {
		0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
		0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
		0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
		0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
		0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
		0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
		0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
		0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
		0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
		0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
		0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
		0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
		0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
		0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
		0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
		0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16};
	unsigned int result = 0;
	for (int i = 1; i <= 4; i++)
	{
		unsigned int byte_i = (rotWord >> (32 - i * 8)) & 0xFF;
		unsigned int subB = subWordArray[byte_i];
		result = (result << 8) | subB;
	}
	return result;
}

unsigned int xorRcon(unsigned int subWord, int j)
{
	int Rc[] = {
		0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
		0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39};
	unsigned int byte_1 = (subWord >> 24) & 0xFF;
	unsigned int byte_234 = subWord & 0xFFFFFF;
	unsigned int resultXor = (byte_1 ^ Rc[j]) & 0xFF;
	unsigned int result = (resultXor << 24) | byte_234;
	return result;
}

unsigned int G(unsigned int word, int j)
{
	unsigned int rotW = rotWord(word);
	unsigned int subW = subWord(rotW);
	unsigned int result = xorRcon(subW, j);
	return result;
}

// Hàm mở rộng khóa.
unsigned int *keyExpansion(unsigned int arrayWord[4])
{
	unsigned int *word = new unsigned int[44];
	word[0] = arrayWord[0];
	word[1] = arrayWord[1];
	word[2] = arrayWord[2];
	word[3] = arrayWord[3];
	for (int i = 4; i <= 44; i++)
	{
		if (i % 4 == 0)
			word[i] = G(word[i - 1], i / 4) ^ word[i - 4];
		else
			word[i] = word[i - 1] ^ word[i - 4];
		// printf("\nword[%d] = ", i); showWord(word[i]);
	}
	return word;
}

// Mã hóa AES.
unsigned int *AddRoundKey(unsigned int state[4], unsigned int *arrayKey)
{
	unsigned int *result = new unsigned int[4];
	for (int i = 0; i < 4; i++)
		result[i] = state[i] ^ arrayKey[i];
	/*
	cout << "\nAddRoundKey" << endl;
	for (int i = 0; i < 4; i++)	{
		printf("\n\t"); showWord(result[i]);
	}
	*/
	return result;
}

unsigned int *SubBytes(unsigned int state[4])
{
	unsigned int *result = new unsigned int[4];
	for (int i = 0; i < 4; i++)
		result[i] = subWord(state[i]);
	/*cout << "\nSubBytes:" << endl;
	for (int i = 0; i < 4; i++)
	{
		cout << "\n\t"; showWord(result[i]);
	}*/
	return result;
}

unsigned int *ShiftRows(unsigned int state[4])
{
	unsigned int *result = new unsigned int[4];
	for (int i = 0; i < 4; i++)
	{
		unsigned int byte_1 = state[i] & 0xFF000000;
		unsigned int byte_2 = state[(i + 1) % 4] & 0xFF0000;
		unsigned int byte_3 = state[(i + 2) % 4] & 0xFF00;
		unsigned int byte_4 = state[(i + 3) % 4] & 0xFF;
		result[i] = byte_1 | byte_2 | byte_3 | byte_4;
	}
	/*cout << "\nShiftRows:" << endl;
	for (int i = 0; i < 4; i++)
	{
		cout << "\n\t"; showWord(result[i]);
	}*/
	return result;
}

unsigned int multiply_double(unsigned int word)
{
	unsigned int result = word << 1;
	result > 256 ? result ^= 0x11B : result;
	result = result & 0xFF;
	return result;
}

unsigned int multiply_triple(unsigned int word)
{
	unsigned int result = word ^ multiply_double(word);
	result = result & 0xFF;
	return result;
}

unsigned int multiply_column(unsigned int word)
{
	unsigned int result;
	unsigned int byte_1 = (word >> 24) & 0xFF;
	unsigned int byte_2 = (word >> 16) & 0xFF;
	unsigned int byte_3 = (word >> 8) & 0xFF;
	unsigned int byte_4 = word & 0xFF;

	unsigned int result_1 = multiply_double(byte_1) ^ multiply_triple(byte_2) ^ byte_3 ^ byte_4;
	unsigned int result_2 = byte_1 ^ multiply_double(byte_2) ^ multiply_triple(byte_3) ^ byte_4;
	unsigned int result_3 = byte_1 ^ byte_2 ^ multiply_double(byte_3) ^ multiply_triple(byte_4);
	unsigned int result_4 = multiply_triple(byte_1) ^ byte_2 ^ byte_3 ^ multiply_double(byte_4);

	result = (result_1 << 24) | (result_2 << 16) | (result_3 << 8) | result_4;
	// cout << "\n\t"; showWord(result);
	return result;
}

unsigned int *MixColumns(unsigned int state[4])
{
	unsigned int *result = new unsigned int[4];
	// cout << "\nMixColumns:" << endl;
	for (int i = 0; i < 4; i++)
	{
		result[i] = multiply_column(state[i]);
	}
	return result;
}

void showMatrix(unsigned int word[4])
{
	for (int i = 0; i < 4; i++)
	{
		cout << "\n\t";
		showWord(word[i]);
	}
}

string matrixToStr(unsigned int * word) {
	string str = "";
	// show matrix
	for (int i = 0; i < 4; i++)
	{
		str += wordToStr(word[i]);
	}
	return str;
}

unsigned int *EncryptionAES(unsigned int state[4], unsigned int arrayKey[4])
{
	unsigned int *key = keyExpansion(arrayKey);
	state = AddRoundKey(state, &key[0]);
	// cout << "\nAES Encryption:" << endl;
	for (int j = 1; j <= 9; j++)
	{
		state = SubBytes(state);
		state = ShiftRows(state);
		state = MixColumns(state);
		state = AddRoundKey(state, &key[4 * j]);
		// printf("\nStep %d:", j);
		// showMatrix(state);
	}
	// Vòng thứ 10.
	// cout << "\nStep 10:";
	state = SubBytes(state);
	state = ShiftRows(state);
	state = AddRoundKey(state, &key[40]);
	// showMatrix(state);
	unsigned int *result = new unsigned int[4];
	result = state;
	return result;
}

// Giải mã AES.
unsigned int *InvShiftRows(unsigned int state[4])
{
	unsigned int *result = new unsigned int[4];
	for (int i = 0; i < 4; i++)
	{
		unsigned int byte_1 = state[i] & 0xFF000000;
		unsigned int byte_2 = state[(i + 3) % 4] & 0xFF0000;
		unsigned int byte_3 = state[(i + 2) % 4] & 0xFF00;
		unsigned int byte_4 = state[(i + 1) % 4] & 0xFF;
		result[i] = byte_1 | byte_2 | byte_3 | byte_4;
	}
	return result;
}

unsigned int InvSubWord(unsigned int word)
{
	int InvS[] = {
		0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
		0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
		0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
		0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
		0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
		0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
		0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
		0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
		0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
		0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
		0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
		0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
		0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
		0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
		0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
		0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};
	unsigned int result = 0;
	for (int i = 1; i <= 4; i++)
	{
		unsigned int byte_i = (word >> (32 - i * 8)) & 0xFF;
		unsigned int subB = InvS[byte_i];
		result = (result << 8) | subB;
	}
	return result;
}

unsigned int *InvSubBytes(unsigned int state[4])
{
	unsigned int *result = new unsigned int[4];
	for (int i = 0; i < 4; i++)
		result[i] = InvSubWord(state[i]);
	return result;
}

unsigned int multiply_9(unsigned int word)
{
	unsigned int result = (word << 3) ^ word;
	if (result > (256 << 2))
		result ^= (0x11b << 2);
	if (result > (256 << 1))
		result ^= (0x11b << 1);
	if (result > 256)
		result ^= 0x11b;
	result &= 0xFF;
	return result;
}

unsigned int multiply_B(unsigned int word)
{
	unsigned int result = (word << 3) ^ (word << 1) ^ word;
	if (result > (256 << 2))
		result ^= (0x11b << 2);
	if (result > (256 << 1))
		result ^= (0x11b << 1);
	if (result > 256)
		result ^= 0x11b;
	result &= 0xFF;
	return result;
}
unsigned int multiply_D(unsigned int word)
{
	unsigned int result = (word << 3) ^ (word << 2) ^ word;
	if (result >= (256 << 2))
		result ^= (0x11b << 2);
	if (result >= (256 << 1))
		result ^= (0x11b << 1);
	if (result >= 256)
		result ^= 0x11b;
	result &= 0xFF;
	return result;
}

unsigned int multiply_E(unsigned int word)
{
	unsigned int result = (word << 3) ^ (word << 2) ^ (word << 1);
	if (result >= (256 << 2))
		result ^= (0x11b << 2);
	if (result >= (256 << 1))
		result ^= (0x11b << 1);
	if (result >= 256)
		result ^= 0x11b;
	result &= 0xFF;
	return result;
}

unsigned int InvMultiply_column(unsigned int word)
{
	unsigned int result;
	unsigned int byte_1 = (word >> 24) & 0xFF;
	unsigned int byte_2 = (word >> 16) & 0xFF;
	unsigned int byte_3 = (word >> 8) & 0xFF;
	unsigned int byte_4 = word & 0xFF;

	unsigned int result_1 = multiply_E(byte_1) ^ multiply_B(byte_2) ^ multiply_D(byte_3) ^ multiply_9(byte_4);
	unsigned int result_2 = multiply_9(byte_1) ^ multiply_E(byte_2) ^ multiply_B(byte_3) ^ multiply_D(byte_4);
	unsigned int result_3 = multiply_D(byte_1) ^ multiply_9(byte_2) ^ multiply_E(byte_3) ^ multiply_B(byte_4);
	unsigned int result_4 = multiply_B(byte_1) ^ multiply_D(byte_2) ^ multiply_9(byte_3) ^ multiply_E(byte_4);

	result = (result_1 << 24) | (result_2 << 16) | (result_3 << 8) | result_4;
	return result;
}

unsigned int *InvMixColumns(unsigned int state[4])
{
	unsigned int *result = new unsigned int[4];
	for (int i = 0; i < 4; i++)
		result[i] = InvMultiply_column(state[i]);
	return result;
}

unsigned int *DecryptionAES(unsigned int Cipher[4], unsigned int arrayKey[4])
{
	unsigned int *key = keyExpansion(arrayKey);
	unsigned int *state = AddRoundKey(Cipher, &key[40]);
	// cout << "\nAES Decryption:" << endl;
	for (int j = 1; j <= 9; j++)
	{
		state = InvShiftRows(state);
		state = InvSubBytes(state);
		state = AddRoundKey(state, &key[40 - 4 * j]);
		state = InvMixColumns(state);
		// printf("\nStep %d:", j);
		// showMatrix(state);
	}
	// Vòng thứ 10.
	// cout << "\nStep 10:";
	state = InvShiftRows(state);
	state = InvSubBytes(state);
	state = AddRoundKey(state, &key[0]);
	// showMatrix(state);
	unsigned int *result = new unsigned int[4];
	result = state;
	return result;
}