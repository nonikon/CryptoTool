#ifndef _ENCODE_H_
#define _ENCODE_H_

unsigned AsciiToInteger(const char* str, char** ep, unsigned base);
int TrimSpace(char* s);

int HexCharsToBinary(char* s);
int Base64CharsToBinary(char* s);
int CArrayCharsToBinary(char* s);
int CStringCharsToBinary(char* s);
int TextCharsToBinary(char* s);

char* BinaryToHexChars(const unsigned char* b, unsigned l);
char* BinaryToBase64Chars(const unsigned char* b, unsigned l);
char* BinaryToCArrayChars(const unsigned char* b, unsigned l);
char* BinaryToCStringChars(const unsigned char* b, unsigned l);
char* BinaryToTextChars(const unsigned char* b, unsigned l);

#endif