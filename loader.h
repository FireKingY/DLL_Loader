#pragma once
#include "def.h"
#include "Encrypter.h"
using namespace std;

class Loader
{
public:
    Encrypter encrypter;


    Loader(Encrypter encrypter);

    DWORD RVAToVA(DWORD RVA, MoudleInfo &dllInfo);//工具函数

    void loadDlls(vector<PlainFile> &dlls);     //加载接口
    void unloadMoudle(MoudleInfo &dllInfo);     //卸载接口
    void *getFuntionByName(MoudleInfo &dllInfo, const string &name);       //按名字获得导出函数地址
    void *getFuntionByOrd(MoudleInfo &dllInfo, unsigned int ord);           //按名导出序号

    MoudleInfo getMoudleInfo(const string& moudleName);     //通过模块名，获得模块的加载信息

private:
    unordered_map<string, MoudleInfo> dllMap;

    void loadfromstream(MoudleInfo &dllInfo, istream &dllStream);    //真正的加载函数，loadDll主要是准备工作
    MoudleInfo *loadByName(const string &name);                      //递归加载时使用
    void initPEInfo(MoudleInfo &dllInfo, istream &pe);                //读取相关header
    void copyDllToMem(MoudleInfo &dllInfo, istream &pe);                //拉伸拷贝
    void relocate(MoudleInfo &dllInfo);                                   //重定位
    void fixImportAddressTable(MoudleInfo &dllInfo);                        //修复IAT
    bool runDllMain(MoudleInfo &dllInfo, DWORD dwReason, LPVOID lpReserved);  //调用dllMain
};