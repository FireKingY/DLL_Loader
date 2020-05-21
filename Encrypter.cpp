#include "Encrypter.h"

Encrypter::Encrypter(CryptProtocol *prot) : prot(prot) {}

void Encrypter::encryptFiles(vector<PlainFile> &inputFiles, const fs::path &outputFilePath = "")
{
    cout << "encrypting files" << endl;

    ofstream ofs;
    istream is(nullptr);

    ofs.open(outputFilePath, ios_base::binary);
    for (auto &file : inputFiles)
        prot->encrypt(file, ofs);

    ofs.close();

    cout << "files encrypted" << endl
         << endl;
}

vector<PlainFile> Encrypter::decryptFile(const fs::path &inputFilePath)
{
    cout << "decrypting file:\t" << inputFilePath.filename() << endl;
    ifstream ifs;

    ifs.open(inputFilePath, ios::binary);
    auto files = decryptFile(ifs);
    ifs.close();

    cout << "file decrypted" << endl << endl;

    return files;
}

vector<PlainFile> Encrypter::decryptFile(istream &is)
{
    ostream os(nullptr);
    vector<PlainFile> files;

    while (true)
    {
        auto file = prot->decrypt(is);
        if (file.pStBuf == nullptr)
            break;
        files.push_back(file);
    }
    return files;
}