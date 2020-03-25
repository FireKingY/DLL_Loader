#pragma once
#include "def.h"
using namespace std;

namespace fs = std::filesystem;

struct DecryptedFile
{
    string fileName;
    streambuf *pStBuf;
    DecryptedFile(char *fileName, streambuf *pStBuf);
    DecryptedFile();
    ~DecryptedFile();
};

class CryptProtocol
{
public:
    virtual void encrypt(const fs::path &filePath, ofstream &ofs);
    virtual DecryptedFile decrypt(ifstream &ifs);
};


class Encrypter
{
public:
    Encrypter(CryptProtocol* prot);
    void encryptFiles(vector<fs::path> &inputFileNames, const fs::path &outputFilePath);
    vector<DecryptedFile> decryptFile(const fs::path &inputFileName);

    CryptProtocol* prot;
};
