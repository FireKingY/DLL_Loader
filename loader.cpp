#include <fstream>
#include <cstring>
#include <locale>
#include <algorithm>
#include "loader.h"
#include "def.h"
using namespace std;

MoudleInfo::MoudleInfo() : count(0), base(nullptr), pStBuf(nullptr) {}

MoudleInfo *Loader::loadByName(const string &name)
{
    auto lowerName = name;
    transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
    auto &dllInfo = dllMap[lowerName];
    if (dllInfo.count >= 1)
    {
        ++dllInfo.count;
        return &dllInfo;
    }
    else if (dllInfo.pStBuf != nullptr)
    {
        istream dllStream(dllInfo.pStBuf);
        loadfromstream(dllInfo, dllStream);
        dllInfo.count = 1;
        return &dllInfo;
    }
    else
        return nullptr;
}

void Loader::loadEncryptedDlls(fs::path &filePath)
{
    auto dlls = encrypter.decryptFile(filePath);
    // istream dllStream(nullptr);
    for (auto &dll : dlls)
    {
        transform(dll.fileName.begin(), dll.fileName.end(), dll.fileName.begin(), ::tolower);
        dllMap[dll.fileName].pStBuf = dll.pStBuf;
    }

    for (auto &dll : dlls)
    {
        auto &dllInfo = dllMap[dll.fileName];
        if (dllInfo.count > 0)
        {
            ++dllInfo.count;
            continue;
        }
        else
            dllInfo.count = 1;
        istream dllStream(dll.pStBuf);
        loadfromstream(dllInfo, dllStream);
    }
}

DWORD Loader::RVAToVA(DWORD RVA, MoudleInfo &dllInfo)
{
    return RVA + reinterpret_cast<uint32_t>(dllInfo.base);
}

void Loader::loadfromstream(MoudleInfo &dllInfo, istream &dllStream)
{

    initPEInfo(dllInfo, dllStream);
    //allocate mem for image 可读可写可执行
    dllInfo.base = VirtualAlloc(nullptr, dllInfo.peInfo.NtHeaders.OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    copyDllToMem(dllInfo, dllStream);
    relocate(dllInfo);
    fixImportTable(dllInfo);
}
void Loader::loadFromFile(const fs::path &filePath)
{
    MoudleInfo &dllInfo = dllMap[filePath.filename().string()];
    // FIXME: 多线程安全？
    if (dllInfo.count > 0)
    {
        ++dllInfo.count;
        return;
    }
    else
        dllInfo.count = 1;

    ifstream dllStream;
    dllStream.open(filePath, ios_base::binary);
    loadfromstream(dllInfo, dllStream);
    dllStream.close();

    return;
}

void Loader::unloadMoudle(MoudleInfo &dllInfo)
{
    // FIXME:出于多线程考虑，dllInfo需要加锁？
    if (dllInfo.count > 1)
        --dllInfo.count;
    else if (dllInfo.count == 1)
    {
        --dllInfo.count;
        VirtualFree(dllInfo.base, 0, MEM_RELEASE);
    }
    else
        dllInfo.count = 0;
}

void Loader::initPEInfo(MoudleInfo &dllInfo, istream &dllStream)
{
    dllStream.seekg(0);
    dllStream.read(reinterpret_cast<char *>(&(dllInfo.peInfo.DosHeader)), sizeof(dllInfo.peInfo.DosHeader)); //read dosHeader
    dllStream.seekg(dllInfo.peInfo.DosHeader.e_lfanew);                                                      //locate ntHeader
    dllStream.read((char *)(&(dllInfo.peInfo.NtHeaders)), sizeof(dllInfo.peInfo.NtHeaders));                 // read ntHeader

    IMAGE_SECTION_HEADER sectionHeader;
    for (int i = 0; i < dllInfo.peInfo.NtHeaders.FileHeader.NumberOfSections; ++i) // read sectionHeaders
    {
        dllStream.read(reinterpret_cast<char *>(&sectionHeader), sizeof(sectionHeader));
        dllInfo.peInfo.SectionHeaders.push_back(sectionHeader);
    }

    return;
}

void Loader::copyDllToMem(MoudleInfo &dllInfo, istream &pe)
{

    // copy sections to mem
    char buf[BUFFER_SIZE];
    //content before sections
    uint32_t remainSize = dllInfo.peInfo.SectionHeaders[0].PointerToRawData;
    void *curPos = reinterpret_cast<void *>(RVAToVA(0, dllInfo));
    pe.seekg(ios::beg);
    while (remainSize > BUFFER_SIZE)
    {
        pe.read(buf, BUFFER_SIZE);
        memcpy(curPos, buf, BUFFER_SIZE);
        remainSize -= BUFFER_SIZE;
        curPos = reinterpret_cast<void *>(reinterpret_cast<uint32_t>(curPos) + BUFFER_SIZE);
    }
    pe.read(buf, remainSize);
    memcpy(curPos, buf, remainSize);

    for (auto &sectionHeader : dllInfo.peInfo.SectionHeaders)
    {
        remainSize = sectionHeader.SizeOfRawData;
        curPos = reinterpret_cast<void *>(RVAToVA(sectionHeader.VirtualAddress, dllInfo));
        pe.seekg(sectionHeader.PointerToRawData);

        while (remainSize > BUFFER_SIZE)
        {
            pe.read(buf, BUFFER_SIZE);
            memcpy(curPos, buf, BUFFER_SIZE);
            remainSize -= BUFFER_SIZE;
            curPos = reinterpret_cast<void *>(reinterpret_cast<uint32_t>(curPos) + BUFFER_SIZE);
        }
        pe.read(buf, remainSize);
        memcpy(curPos, buf, remainSize);
    }
    return;
}

void Loader::relocate(MoudleInfo &dllInfo)
{
    void *pRelocateTable = reinterpret_cast<void *>(RVAToVA(dllInfo.peInfo.NtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress, dllInfo));
    void *pRelocateTableEnd = reinterpret_cast<void *>(reinterpret_cast<uint32_t>(pRelocateTable) + dllInfo.peInfo.NtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);

    void *curTablePos = pRelocateTable;
    while (curTablePos < pRelocateTableEnd)
    {
        PIMAGE_BASE_RELOCATION rel = static_cast<PIMAGE_BASE_RELOCATION>(curTablePos);
        uint16_t *offsets_start = reinterpret_cast<uint16_t *>(reinterpret_cast<uint32_t>(rel) + sizeof(*rel));
        uint16_t *offset = offsets_start;
        for (; reinterpret_cast<uint32_t>(offset) - reinterpret_cast<uint32_t>(offsets_start) < rel->SizeOfBlock - sizeof(*rel);
             offset = reinterpret_cast<uint16_t *>(reinterpret_cast<uint32_t>(offset) + sizeof(uint16_t)))
        {
            if ((*offset & 0xf000) != 0x3000) //高四位为0x0011时有效，否则为占位项
                continue;
            void **pPData = reinterpret_cast<void **>(RVAToVA(rel->VirtualAddress, dllInfo) + ((*offset) & 0x0fff));
            *pPData = reinterpret_cast<void *>(reinterpret_cast<uint32_t>(*pPData) + reinterpret_cast<uint32_t>(dllInfo.base) - dllInfo.peInfo.NtHeaders.OptionalHeader.ImageBase);
        }
        curTablePos = reinterpret_cast<void *>(reinterpret_cast<uint32_t>(curTablePos) + rel->SizeOfBlock);
    }
}

void *Loader::getFuntionByName(MoudleInfo &dllInfo, const string &name)
{
    static PIMAGE_EXPORT_DIRECTORY pExDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(RVAToVA(dllInfo.peInfo.NtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, dllInfo));
    static uint32_t *addressTable = reinterpret_cast<uint32_t *>(RVAToVA(pExDir->AddressOfFunctions, dllInfo));
    static uint32_t *namePointerTable = reinterpret_cast<uint32_t *>(RVAToVA(pExDir->AddressOfNames, dllInfo));
    static uint16_t *ordinalTable = reinterpret_cast<uint16_t *>(RVAToVA(pExDir->AddressOfNameOrdinals, dllInfo));

    //get ordinal
    auto namePointer = namePointerTable;
    unsigned int count = 0;

    //搜索导出名字表中是否存在对应名字的函数
    for (; count < pExDir->NumberOfNames; ++count)
    {
        if (strcmp(name.c_str(), reinterpret_cast<char *>(RVAToVA(*namePointer, dllInfo))) == 0)
            break;
        ++namePointer;
    }
    if (count >= pExDir->NumberOfNames)
        return nullptr;

    auto rva = (addressTable[ordinalTable[count]]); //序号表和名字表是一一对应的， 序号表中存放的内容为该函数在地址表中索引
    return reinterpret_cast<void *>(RVAToVA(rva, dllInfo));
}
void *Loader::getFuntionByOrd(MoudleInfo &dllInfo, unsigned int ord)
{
    static PIMAGE_EXPORT_DIRECTORY pExDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(RVAToVA(dllInfo.peInfo.NtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, dllInfo));
    static uint32_t *addressTable = reinterpret_cast<uint32_t *>(RVAToVA(pExDir->AddressOfFunctions, dllInfo));

    ord -= pExDir->Base; // ordinal table中存储的是函数在 address table中的索引
    return reinterpret_cast<void *>(RVAToVA(addressTable[ord], dllInfo));
}

void Loader::fixImportTable(MoudleInfo &dllInfo)
{
    // FIXME: 未处理绑定导入表
    PIMAGE_IMPORT_DESCRIPTOR pImDes = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(RVAToVA(dllInfo.peInfo.NtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, dllInfo));
    // PIMAGE_BOUND_IMPORT_DESCRIPTOR pBImDes = reinterpret_cast<PIMAGE_BOUND_IMPORT_DESCRIPTOR>(RVAToVA(dllInfo.peInfo.NtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress, dllInfo));
    while (pImDes->Characteristics != 0) // 0 for terminating null import descriptor
    {
        void **pPAddressTable = reinterpret_cast<void **>(RVAToVA(pImDes->FirstThunk, dllInfo));
        char **pPNameTable = reinterpret_cast<char **>(RVAToVA(pImDes->OriginalFirstThunk, dllInfo));
        void *fun = nullptr;

        char *moudleName = reinterpret_cast<char *>(RVAToVA(pImDes->Name, dllInfo));
        string str_moudleName(moudleName);

        auto pDllInfo = loadByName(str_moudleName);
        if (pDllInfo != nullptr)
        {
            while (*pPNameTable != nullptr) // end of imports
            {
                if (IMAGE_SNAP_BY_ORDINAL32(reinterpret_cast<uint32_t>(*pPNameTable)))
                {
                    // 按序号导入
                    fun = getFuntionByOrd(*pDllInfo, (uint32_t)(*pPNameTable) & 0xffff);
                }
                else
                {
                    uint16_t *pHint = reinterpret_cast<uint16_t *>(RVAToVA(reinterpret_cast<uint32_t>(*pPNameTable), dllInfo));
                    char *pFunctionName = reinterpret_cast<char *>(pHint + 1);
                    fun = getFuntionByName(*pDllInfo, pFunctionName);
                }
                if (reinterpret_cast<uint32_t>(fun) == reinterpret_cast<uint32_t>(*pPAddressTable))
                    break;
                *pPAddressTable = reinterpret_cast<void *>(fun);
                ++pPAddressTable;
                ++pPNameTable;
            }
        }
        else
        {
            auto hMoudle = LoadLibrary(moudleName);

            while (*pPNameTable != nullptr) // end of imports
            {
                if (IMAGE_SNAP_BY_ORDINAL32(reinterpret_cast<uint32_t>(*pPNameTable)))
                {
                    // 按序号导入
                    //TODO
                    fun = (void *)GetProcAddress(hMoudle, (char *)((uint32_t)(*pPNameTable) & 0xffff));
                }
                else
                {
                    uint16_t *pHint = reinterpret_cast<uint16_t *>(RVAToVA(reinterpret_cast<uint32_t>(*pPNameTable), dllInfo));
                    char *pFunctionName = reinterpret_cast<char *>(pHint + 1);
                    fun = (void *)GetProcAddress(hMoudle, pFunctionName);
                }
                if (reinterpret_cast<uint32_t>(fun) == reinterpret_cast<uint32_t>(*pPAddressTable))
                    break;
                *pPAddressTable = reinterpret_cast<void *>(fun);
                ++pPAddressTable;
                ++pPNameTable;
            }
        }
        ++pImDes;
    }

}

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

void encrypt()
{

    Encrypter cp;
    vector<fs::path> fileNames;
    fileNames.push_back("C:\\Users\\Administrator\\source\\repos\\test2\\Release\\test2.dll");
    fileNames.push_back("C:\\Users\\Administrator\\source\\repos\\testDlll\\Release\\testDlll.dll");
    
    cp.encryptFiles(fileNames, "output");
}

int main()
{
    // dlltest();
    encrypt();
    Loader loader;
    auto path = fs::current_path() / "output";
    loader.loadEncryptedDlls(path);

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