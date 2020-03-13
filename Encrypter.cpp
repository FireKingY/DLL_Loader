#include <cstring>
#include "Encrypter.h"
#include "def.h"

DecryptedFile::DecryptedFile(char *fileName, streambuf *pStBuf) : fileName(string(fileName)), pStBuf(pStBuf) {}
DecryptedFile::DecryptedFile() : pStBuf(nullptr) {}
DecryptedFile::~DecryptedFile()
{
    //FIXME: 内存泄漏警告
    // delete pStBuf;
}

void Encrypter::encryptFiles(vector<fs::path> &filePaths, const string &outputFileName)
{
    char buffer[BUFFER_SIZE];
    ofstream ofs;
    ifstream ifs;

    ofs.open(outputFileName, ios_base::binary);
    for (auto &filePath : filePaths)
    {
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
        while (true)
        {
            ifs.read(buffer, BUFFER_SIZE);
            if (!ifs.eof())
                ofs.write(buffer, BUFFER_SIZE);
            else
            {
                ofs.write(buffer, ifs.gcount());
                break;
            }
        }
        ifs.close();
    }

    ofs.close();
}

vector<DecryptedFile> Encrypter::decryptFile(const fs::path &inputFilePath)
{
    ifstream ifs;
    ostream os(nullptr);
    vector<DecryptedFile> files;

    ifs.open(inputFilePath, ios::binary);
    bool end = false;
    while (!end)
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
                end = true;
                break;
            }
            ++cur;
        }

        if (end)
            break;

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
        auto tmp = DecryptedFile(fileName, ps);
        files.push_back(tmp);
    }
    ifs.close();
    return files;
}

// int main()
// {
//     Encrypter cp;
// //     vector<fs::path> fileNames;
// //     fileNames.push_back("1.dll");
// //     fileNames.push_back("2.dll");
// //     cp.encryptFiles(fileNames, "output");

//     auto files = cp.decryptFile("output");
//     istream is(nullptr);
//     for (auto &file : files)
//     {
//         is.rdbuf(file.pStBuf);
//         char buf[100] = {0};
//         is.read(buf, 99);
//         cout << buf << endl;
//     }
// }