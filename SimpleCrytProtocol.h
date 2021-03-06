#pragma once
#include "def.h"
#include "Encrypter.h"

class SimpleCryptProtocol : public CryptProtocol
{
public:
    void encrypt(const PlainFile &file, ofstream &ofs);
    PlainFile decrypt(istream &is);


    // 栅栏加密 栅栏长度
    int fenceSize = 5;
    // 移动长度
    int movesteps = 2;
    // xor数字      (a XOR b) XOR b = a
    char magicNum = 0x77;

private:
    void reverse(char* buf, int start, int end);
    void rotate(char* buf, int bufSize, int steps);

};