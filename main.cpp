#include "loader.h"
#include "SimpleCrytProtocol.h"
#include "Encrypter.h"
#include "getDll.h"
using namespace std;

string outputPath = ".\\output";
string outputFilename = "encrypted";
fs::path outputFileFullPath = outputPath + "\\" + outputFilename;
fs::path recvFileFullPath = outputPath + "\\" + "recv_" + outputFilename;

int main()
{
    typedef void (*FUN)();
    SimpleCryptProtocol prot;
    Encrypter cp(&prot);
    Loader loader(cp);
    PlainFile dllFile;
    vector<PlainFile> dlls;

    //检查是否存在加密后的文件
    if (filesystem::exists(outputFileFullPath))
        dlls = cp.decryptFile(outputFileFullPath);
    else
    {
        //通过网络传输获得dll
        dllFile = getDll("127.0.0.1", 1234);
        //构造参数
        dlls.push_back(dllFile);
        cp.encryptFiles(dlls, outputFileFullPath);
    }
    //使用加载模块进行加载
    loader.loadDlls(dlls);
    loader.loadDlls(dlls);
    //获取加载信息
    auto moudleInfo = loader.getMoudleInfo("InfoReader.dll"); //全小写

    //通过两种方式获得导出函数地址
    FUN cInfo = (FUN)(loader.getFuntionByName(moudleInfo, "collectInfo"));
    cInfo = (FUN)(loader.getFuntionByOrd(moudleInfo, 2));

    //调用运行
    if (cInfo != nullptr)
    {
        cInfo();
    }

    loader.unloadMoudle(moudleInfo);
    loader.unloadMoudle(moudleInfo);
}