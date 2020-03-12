#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <iostream>
using namespace std;

namespace fs = std::filesystem;

struct DecryptedFile
{
    string fileName;
    streambuf* pStBuf;
    DecryptedFile(char* fileName, streambuf* pStBuf);
    DecryptedFile();
    ~DecryptedFile();
};

class Encrypter
{
public:
    void encryptFiles(vector<fs::path> &inputFileNames, const string &outputFileName);
    vector<DecryptedFile> decryptFile(const fs::path &inputFileName);
};