#include "loader.h"
#include "SimpleCrytProtocol.h"
#include "Encrypter.h"
#include "getEncryptedDll.h"
using namespace std;

string outputPath = ".\\output";
string outputFilename = "encrypted";
fs::path outputFileFullPath = outputPath + "\\" + outputFilename;
fs::path recvFileFullPath = outputPath + "\\" + "recv_" + outputFilename;

void dlltest()
{

 //    LoadLibrary("C:\\Users\\Administrator\\source\\repos\\testDlll\\Release\\testDlll.dll");
    // LoadLibrary("C:\\Users\\Administrator\\source\\repos\\test2\\Release\\test2.dll");
     auto hd = LoadLibrary("C:\\Users\\Administrator\\source\\repos\\InfoReader\\Debug\\InfoReader.dll");
  //   LoadLibrary("C:\\Users\\Administrator\\source\\repos\\dll3\\Release\\dll3.dll");

  //  FreeLibrary(hd);
  //  FreeLibrary(hd);
    if (hd == NULL)
    {
        int errCode = GetLastError();
        cout << errCode << endl;
        FreeLibrary(hd);
        return;
    }
    typedef void(*FUN)();
    FUN f = (FUN)GetProcAddress(hd, (char *)"collectInfo");
    if (f != nullptr)
        f();
    FreeLibrary(hd);
    return;
}

void encrypt(Encrypter cp)
{
    vector<fs::path> fileNames;
    fileNames.push_back("C:\\Users\\Administrator\\source\\repos\\dll3\\Release\\dll3.dll");
    fileNames.push_back("C:\\Users\\Administrator\\source\\repos\\testDlll\\Release\\testDlll.dll");
    fileNames.push_back("C:\\Users\\Administrator\\source\\repos\\test2\\Release\\test2.dll");
    fileNames.push_back("C:\\Users\\Administrator\\source\\repos\\infoReader\\Debug\\infoReader.dll");

    cp.encryptFiles(fileNames, outputFileFullPath);
}

int main()
{
 //   dlltest();
    // CryptProtocol prot;
    SimpleCryptProtocol prot;
    Encrypter cp(&prot);
    encrypt(cp);
    auto fileBuf = getEncryptedDll();
    istream recvdFile(fileBuf.get());

    Loader loader(cp);
    loader.loadEncryptedDlls(recvdFile);
    // loader.loadEncryptedDlls(recvFileFullPath);

    auto moudleInfo = loader.dllMap["inforeader.dll"];
    auto dll3Info = loader.dllMap["dll3.dll"];

    typedef void (*FUN)();

    FUN cInfo = reinterpret_cast<FUN>(loader.getFuntionByName(moudleInfo, "collectInfo"));
    // if (test != nullptr)
    //     test();

    if (cInfo != nullptr)
        cInfo();

    // loader.unloadMoudle(moudleInfo1);
    // loader.unloadMoudle(moudleInfo2);
}