#pragma once
#include "def.h"
using namespace std;

namespace fs = std::filesystem;

struct DecryptedFile
{
    string fileName;
    shared_ptr<streambuf> pStBuf;
    DecryptedFile(char *fileName, shared_ptr<streambuf> pStBuf);
    DecryptedFile(char *fileName, streambuf *pStBuf);
    DecryptedFile();
    ~DecryptedFile();
};

class CryptProtocol
{
public:
    virtual void encrypt(const fs::path &filePath, ofstream &ofs);
    virtual DecryptedFile decrypt(istream &is);
};


class Encrypter
{
public:
    Encrypter(CryptProtocol* prot);
    void encryptFiles(vector<fs::path> &inputFileNames, const fs::path &outputFilePath);
    vector<DecryptedFile> decryptFile(const fs::path &inputFileName);
    vector<DecryptedFile> decryptFile(istream &is);

    CryptProtocol* prot;
};
