#include "SimpleCrytProtocol.h"
#include "def.h"
using namespace std;

namespace fs = std::filesystem;

void encryptTest(vector<fs::path> &paths, const string &outputName, Encrypter cp)
{

    cp.encryptFiles(paths, outputName);
}

void decryptTest(fs::path &filePath, Encrypter cp)
{
    auto dlls = cp.decryptFile(filePath);
    for (auto &dll : dlls)
    {
        istream is(dll.pStBuf);
        ofstream ofs;
        auto oPath =filePath.parent_path().string() + "\\" +dll.fileName;
        ofs.open(oPath + ".dll", ios_base::binary);

        char buf[BUFFER_SIZE];
        while (true)
        {
            is.read(buf, BUFFER_SIZE);
            if (!is.eof())
                ofs.write(buf, BUFFER_SIZE);
            else
            {
                ofs.write(buf, is.gcount());
                break;
            }
        }
    }
}

bool compareTwoFile(const fs::path &p1, const fs::path &p2)
{
    auto fileSize1 = (uint64_t)fs::file_size(p1);
    auto fileSize2 = (uint64_t)fs::file_size(p2);
    if (fileSize1 != fileSize2)
        return false;

    ifstream ifs1;
    ifstream ifs2;
    ifs1.open(p1, ios::binary);
    ifs2.open(p2, ios::binary);

    char c1;
    char c2;
    int loc = 0;
    while (true)
    {
        ifs1.read(&c1, sizeof(char));
        if(ifs1.eof())
            return true;
        ifs2.read(&c2, sizeof(char));
        ++loc;

        if (c1 != c2)
        {
            ifs1.close();
            ifs2.close();
            cout << p1.filename() << "&" << p2.filename() << ":" << loc << endl;
            return false;
        }
    }
    ifs1.close();
    ifs2.close();
    return true;
}

bool cryptProtocolTest(CryptProtocol* prot)
{
    vector<fs::path> fileNames;
    fs::path f1 = "C:\\Users\\Administrator\\source\\repos\\test2\\Release\\test2.dll";
    fs::path f2 = "C:\\Users\\Administrator\\source\\repos\\testDlll\\Release\\testDlll.dll";
    // fs::path f1 = "C:\\Users\\Administrator\\OneDrive\\code\\DLL_Loader\\output\\1";
    // fs::path f2 = "C:\\Users\\Administrator\\OneDrive\\code\\DLL_Loader\\output\\2";
    fileNames.push_back(f1);
    fileNames.push_back(f2);
    auto outputName = ".\\output\\crypted";
    fs::path outputPath = ".\\output\\crypted";
    Encrypter cp(prot);
    encryptTest(fileNames, outputName, cp);
    decryptTest(outputPath, cp);

    for(auto& path:fileNames)
    {
        auto p = outputPath.parent_path().string() +"\\"+ path.filename().string();
        if(!compareTwoFile(path,  p + ".dll"))
            return false;
    }
    return true;
}

int main()
{
    SimpleCryptProtocol scp;
    // CryptProtocol scp;
    if(cryptProtocolTest(&scp))
        cout << "SimpleCryptProtocol passed" << endl;
    else
        cout << "SimpleCryptProtocol failed" << endl;
}