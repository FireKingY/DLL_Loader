#include "loader.h"
#include "SimpleCrytProtocol.h"
using namespace std;

string outputPath = ".\\output";
string outputFilename = "encrypted";
fs::path outputFileFullPath = outputPath + "\\" + outputFilename;

void dlltest()
{

    auto hd = LoadLibrary("C:\\Users\\Administrator\\source\\repos\\testDlll\\Release\\testDlll.dll");
    if (hd == NULL)
    {
        int errCode = GetLastError();
        cout << errCode << endl;
        FreeLibrary(hd);
        return;
    }
    typedef const char *(*FUN)(int a, int b);
    FUN f = (FUN)GetProcAddress(hd, (char *)5);
    if (f != nullptr)
        cout << f(1, 1) << endl;
    FreeLibrary(hd);
    return;
}

void encrypt(Encrypter cp)
{
    vector<fs::path> fileNames;
    fileNames.push_back("C:\\Users\\Administrator\\source\\repos\\test2\\Release\\test2.dll");
    fileNames.push_back("C:\\Users\\Administrator\\source\\repos\\testDlll\\Release\\testDlll.dll");

    cp.encryptFiles(fileNames, outputFileFullPath);
}

int main()
{
    // dlltest();
    // CryptProtocol prot;
    SimpleCryptProtocol prot;
    Encrypter cp(&prot);
    encrypt(cp);

    Loader loader(cp);
    loader.loadEncryptedDlls(outputFileFullPath);

    // auto moudleInfo1 = loader.dllMap["testDlll.dll"];
    auto moudleInfo2 = loader.dllMap["test2.dll"];

    typedef void (*FUN)();
    // FUN fun1 = reinterpret_cast<FUN>(loader.getFuntionByName(moudleInfo1, "msgBox"));
    FUN fun2 = reinterpret_cast<FUN>(loader.getFuntionByName(moudleInfo2, "hello"));

    // if (fun1 != nullptr)
    //     fun1();
    if (fun2 != nullptr)
        fun2();

    // loader.unloadMoudle(moudleInfo1);
    // loader.unloadMoudle(moudleInfo2);
}