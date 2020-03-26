#include "Encrypter.h"

DecryptedFile::DecryptedFile(char *fileName, streambuf *pStBuf):fileName(string(fileName)), pStBuf(shared_ptr<streambuf>(pStBuf)){}
DecryptedFile::DecryptedFile(char *fileName, shared_ptr<streambuf> pStBuf) : fileName(string(fileName)), pStBuf(pStBuf) {}
DecryptedFile::DecryptedFile() : pStBuf(nullptr) {}
DecryptedFile::~DecryptedFile()
{
    //FIXME: 内存泄漏警告
    // delete pStBuf;
}

void CryptProtocol::encrypt(const fs::path &filePath, ofstream &ofs)
{
    ifstream ifs;
    ifs.open(filePath, ios_base::binary);
    //write filename
    auto fileName = filePath.filename().string();
    char tmp = 0;
    ofs.write(fileName.c_str(), fileName.length());
    ofs.write(&tmp, sizeof(char)); // end of filename
    //write filesize
    auto fileSize = (uint64_t)fs::file_size(filePath);
    ofs.write((char *)(&fileSize), sizeof(fileSize));
    //write encrypted content
    char buf;
    while (true)
    {
        ifs.read(&buf, sizeof(buf));
        if (!ifs.eof())
            ofs.write(&buf, sizeof(buf));
        else
            break;
    }
    ifs.close();
}

DecryptedFile CryptProtocol::decrypt(ifstream &ifs)
{

    ostream os(nullptr);
    char fileName[100];
    char *cur = fileName;
    while (true)
    {
        os.rdbuf(new stringbuf);
        ifs.read(cur, sizeof(char));
        *(cur + 1) = 0;
        if (*cur == 0)
            break;
        if (ifs.eof())
        {
            cur[0] = 0;
            return DecryptedFile(fileName, nullptr);
        }
        ++cur;
    }

    uint64_t fileSize;
    ifs.read((char *)&fileSize, sizeof(fileSize));

    char buf[BUFFER_SIZE];
    while (fileSize > BUFFER_SIZE)
    {
        ifs.read(buf, BUFFER_SIZE);
        os.write(buf, BUFFER_SIZE);
        fileSize -= BUFFER_SIZE;
    }
    ifs.read(buf, fileSize);
    os.write(buf, fileSize);
    auto ps = os.rdbuf();
    os.rdbuf(nullptr);
    return DecryptedFile(fileName, ps);
}

Encrypter::Encrypter(CryptProtocol *prot) : prot(prot) {}

void Encrypter::encryptFiles(vector<fs::path> &filePaths, const fs::path &outputFilePath = "encrypted")
{

    ofstream ofs;
    ifstream is;

    ofs.open(outputFilePath, ios_base::binary);
    for (auto &filePath : filePaths)
        prot->encrypt(filePath, ofs);

    ofs.close();
}

vector<DecryptedFile> Encrypter::decryptFile(const fs::path &inputFilePath)
{
    ifstream ifs;
    ostream os(nullptr);
    vector<DecryptedFile> files;

    ifs.open(inputFilePath, ios::binary);
    while (true)
    {
        auto file = prot->decrypt(ifs);
        if (file.pStBuf == nullptr)
            break;
        files.push_back(file);
    }
    ifs.close();
    return files;
}
