#ifndef _ENDEC_H_
#define _ENDEC_H_

int TrimSpace(char* s);

int HexCharsToBinary(char* s);
int Base64CharsToBinary(char* s);
int CArrayCharsToBinary(char* s);
int CStringCharsToBinary(char* s);

char* BinaryToHexChars(unsigned char* b, unsigned l);
char* BinaryToBase64Chars(unsigned char* b, unsigned l);
char* BinaryToCArrayChars(unsigned char* b, unsigned l);
char* BinaryToCStringChars(unsigned char* b, unsigned l);

#endif