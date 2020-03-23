#include <windows.h>
#include <vector>
#include <iostream>
#include "Encrypter.h"
#include <unordered_map>
using namespace std;


struct PE_INFO32
{
    IMAGE_DOS_HEADER DosHeader;
    IMAGE_NT_HEADERS32 NtHeaders;
    vector<IMAGE_SECTION_HEADER> SectionHeaders;
};

struct MoudleInfo
{
    uint32_t count;
    void *base;
    PE_INFO32 peInfo;
    streambuf* pStBuf; // 当dll被解密但尚未被加载时有效，用于在被依赖时定位用
    MoudleInfo();
};

class Loader
{
public:
    unordered_map<string, MoudleInfo> dllMap;
    Encrypter encrypter;

    void loadFromFile(const fs::path& filePath);
    void unloadMoudle(MoudleInfo& dllInfo);
    DWORD RVAToVA(DWORD RVA, MoudleInfo& dllInfo);
    void* getFuntionByName(MoudleInfo& dllInfo, const string& name);
    void* getFuntionByOrd(MoudleInfo& dllInfo, unsigned int ord);
    void loadDecryptedDlls(vector<DecryptedFile>& dlls);
    void loadEncryptedDlls(fs::path& filePath);
    MoudleInfo* loadByName(const string& name);

private:
    void loadfromstream(MoudleInfo& dllInfo, istream& dllStream);
    void initPEInfo(MoudleInfo& dllInfo, istream &pe);
    void copyDllToMem(MoudleInfo& dllInfo, istream &pe);
    void relocate(MoudleInfo& dllInfo);
    void fixImportTable(MoudleInfo& dllInfo);
};