#include "loader.h"
#include "SimpleCrytProtocol.h"
using namespace std;

string outputPath = ".\\output";
string outputFilename = "encrypted";
fs::path outputFileFullPath = outputPath + "\\" + outputFilename;

void dlltest()
{

    LoadLibrary("C:\\Users\\Administrator\\source\\repos\\testDlll\\Release\\testDlll.dll");
    LoadLibrary("C:\\Users\\Administrator\\source\\repos\\test2\\Release\\test2.dll");
    auto hd = LoadLibrary("C:\\Users\\Administrator\\source\\repos\\dll3\\Release\\dll3.dll");
    if (hd == NULL)
    {
        int errCode = GetLastError();
        cout << errCode << endl;
        FreeLibrary(hd);
        return;
    }
    typedef void(*FUN)(int a, int b);
    FUN f = (FUN)GetProcAddress(hd, (char *)"printAddTwice");
    if (f != nullptr)
        f(1, 1);
    FreeLibrary(hd);
    return;
}

void encrypt(Encrypter cp)
{
    vector<fs::path> fileNames;
    fileNames.push_back("C:\\Users\\Administrator\\source\\repos\\dll3\\Release\\dll3.dll");
    fileNames.push_back("C:\\Users\\Administrator\\source\\repos\\testDlll\\Release\\testDlll.dll");
    fileNames.push_back("C:\\Users\\Administrator\\source\\repos\\test2\\Release\\test2.dll");

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
    auto moudleInfo3 = loader.dllMap["dll3.dll"];

    typedef void (*FUN)(int, int);
    // FUN fun1 = reinterpret_cast<FUN>(loader.getFuntionByName(moudleInfo1, "msgBox"));
    FUN printAdd = reinterpret_cast<FUN>(loader.getFuntionByName(moudleInfo2, "printAdd"));
    FUN printAddTwice = reinterpret_cast<FUN>(loader.getFuntionByName(moudleInfo3, "printAddTwice"));

    // if (fun1 != nullptr)
    //     fun1();
    if (printAdd != nullptr)
        printAdd(33,55);
    if (printAddTwice != nullptr)
        printAddTwice(33,55);

    // loader.unloadMoudle(moudleInfo1);
    // loader.unloadMoudle(moudleInfo2);
}