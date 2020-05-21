#pragma once
#include "def.h"
using namespace std;

namespace fs = std::filesystem;


class CryptProtocol
{
public:
    virtual void encrypt(const PlainFile &file, ofstream &ofs) = 0;
    virtual PlainFile decrypt(istream &is) = 0;
};


class Encrypter
{
public:
    Encrypter(CryptProtocol* prot);
    void encryptFiles(vector<PlainFile> &inputFiles, const fs::path &outputFilePath);
    vector<PlainFile> decryptFile(const fs::path &inputFileName);
    vector<PlainFile> decryptFile(istream &is);

    CryptProtocol* prot;
};
