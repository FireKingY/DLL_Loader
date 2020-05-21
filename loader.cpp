#include "loader.h"
#include "def.h"
using namespace std;

MoudleInfo::MoudleInfo() : count(0), base(nullptr), pStBuf(nullptr) {}

PlainFile::PlainFile(char *fileName, uint64_t fileSize, streambuf *pStBuf) : fileName(string(fileName)), fileSize(fileSize), pStBuf(shared_ptr<streambuf>(pStBuf)) {}
PlainFile::PlainFile(char *fileName, uint64_t fileSize, shared_ptr<streambuf> pStBuf) : fileName(string(fileName)), fileSize(fileSize), pStBuf(pStBuf) {}
PlainFile::PlainFile() : fileName(""), fileSize(0), pStBuf(nullptr) {}
PlainFile::~PlainFile()
{
    //使用共享指针无需手动处理
    // delete pStBuf;
}

Loader::Loader(Encrypter encrypter) : encrypter(encrypter) {}

DWORD Loader::RVAToVA(DWORD RVA, MoudleInfo &dllInfo)
{
    return RVA + (uint32_t)(dllInfo.base);
}

void Loader::loadDlls(vector<PlainFile> &dlls)
{
    // FIXME:出于多线程考虑，dllInfo需要加锁？

    cout << "loading Dlls" << endl;

    //为了方便， 名字统一转换到小写英文字母
    for (auto &dll : dlls)
    {
        transform(dll.fileName.begin(), dll.fileName.end(), dll.fileName.begin(), ::tolower);
        dllMap[dll.fileName].pStBuf = dll.pStBuf;
    }

    //逐个进行加载
    for (auto &dll : dlls)
    {
        cout << "\tloading Dll:\t" << dll.fileName << endl;

        auto &dllInfo = dllMap[dll.fileName];
        //判断是否已经加载过
        if (dllInfo.count > 0)
        {
            ++dllInfo.count;
            cout << "\tDll already loaded" << endl
                 << "\t\tcurrent count:" << dllInfo.count << endl;
            continue;
        }
        else
        {

            dllInfo.count = 1;
            dllInfo.name = dll.fileName;
            istream dllStream(dll.pStBuf.get());
            //调用加载函数，进行加载
            loadfromstream(dllInfo, dllStream);

            cout << "\tDll loaded" << endl
                 << "\t\tbase:" << dllInfo.base << endl
                 << "\t\tcount:" << dllInfo.count << endl;
        }
    }

    cout << "Dlls loaded" << endl
         << endl;
}

//进行加载操作
void Loader::loadfromstream(MoudleInfo &dllInfo, istream &dllStream)
{

    initPEInfo(dllInfo, dllStream);
    //allocate mem for image 可读可写可执行
    dllInfo.base = VirtualAlloc(nullptr, dllInfo.peInfo.NtHeaders.OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    copyDllToMem(dllInfo, dllStream);
    relocate(dllInfo);
    fixImportAddressTable(dllInfo);
    //调用dllmain 初始化
    runDllMain(dllInfo, DLL_PROCESS_ATTACH, NULL);
    // 加载已完成 不再需要流buf
    dllInfo.pStBuf.reset();
}

//读取了各种header
void Loader::initPEInfo(MoudleInfo &dllInfo, istream &dllStream)
{
    dllStream.seekg(0);
    dllStream.read((char *)(&(dllInfo.peInfo.DosHeader)), sizeof(dllInfo.peInfo.DosHeader)); //read dosHeader
    dllStream.seekg(dllInfo.peInfo.DosHeader.e_lfanew);                                      //locate ntHeader
    dllStream.read((char *)(&(dllInfo.peInfo.NtHeaders)), sizeof(dllInfo.peInfo.NtHeaders)); // read ntHeader

    IMAGE_SECTION_HEADER sectionHeader;
    for (int i = 0; i < dllInfo.peInfo.NtHeaders.FileHeader.NumberOfSections; ++i) // read sectionHeaders
    {
        dllStream.read((char *)(&sectionHeader), sizeof(sectionHeader));
        dllInfo.peInfo.SectionHeaders.push_back(sectionHeader);
    }
}

//拉伸拷贝
void Loader::copyDllToMem(MoudleInfo &dllInfo, istream &pe)
{

    char buf[BUFFER_SIZE];
    //拷贝第一个section之前的内容
    uint32_t remainSize = dllInfo.peInfo.SectionHeaders[0].PointerToRawData;
    void *curPos = (void *)(RVAToVA(0, dllInfo));
    pe.seekg(ios::beg);
    while (remainSize > BUFFER_SIZE)
    {
        pe.read(buf, BUFFER_SIZE);
        memcpy(curPos, buf, BUFFER_SIZE);
        remainSize -= BUFFER_SIZE;
        curPos = (void *)((uint32_t)(curPos) + BUFFER_SIZE);
    }
    pe.read(buf, remainSize);
    memcpy(curPos, buf, remainSize);

    //拷贝各个section
    for (auto &sectionHeader : dllInfo.peInfo.SectionHeaders)
    {
        remainSize = sectionHeader.SizeOfRawData;
        curPos = (void *)(RVAToVA(sectionHeader.VirtualAddress, dllInfo));
        pe.seekg(sectionHeader.PointerToRawData);

        while (remainSize > BUFFER_SIZE)
        {
            pe.read(buf, BUFFER_SIZE);
            memcpy(curPos, buf, BUFFER_SIZE);
            remainSize -= BUFFER_SIZE;
            curPos = (void *)((uint32_t)(curPos) + BUFFER_SIZE);
        }
        pe.read(buf, remainSize);
        memcpy(curPos, buf, remainSize);
    }
    return;
}

//重定位
void Loader::relocate(MoudleInfo &dllInfo)
{
    void *pRelocateTable = (void *)(RVAToVA(dllInfo.peInfo.NtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress, dllInfo));
    void *pRelocateTableEnd = (void *)((uint32_t)(pRelocateTable) + dllInfo.peInfo.NtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);

    void *curTablePos = pRelocateTable;

    //逐块操作
    while (curTablePos < pRelocateTableEnd)
    {
        PIMAGE_BASE_RELOCATION rel = static_cast<PIMAGE_BASE_RELOCATION>(curTablePos);
        uint16_t *offsets_start = (uint16_t *)((uint32_t)(rel) + sizeof(*rel));
        uint16_t *offset = offsets_start;

        //逐记录操作
        for (; (uint32_t)(offset) - (uint32_t)(offsets_start) < rel->SizeOfBlock - sizeof(*rel);
             offset = (uint16_t *)((uint32_t)(offset) + sizeof(uint16_t)))
        {
            if ((*offset & 0xf000) != 0x3000) //高四位为0x0011时有效，否则为占位项
                continue;
            void **pPData = (void **)(RVAToVA(rel->VirtualAddress, dllInfo) + ((*offset) & 0x0fff));
            *pPData = (void *)((uint32_t)(*pPData) + ((uint32_t)(dllInfo.base) - dllInfo.peInfo.NtHeaders.OptionalHeader.ImageBase));
        }

        curTablePos = (void *)((uint32_t)(curTablePos) + rel->SizeOfBlock);
    }
}

void Loader::fixImportAddressTable(MoudleInfo &dllInfo)
{
    PIMAGE_IMPORT_DESCRIPTOR pImDes = (PIMAGE_IMPORT_DESCRIPTOR)(RVAToVA(dllInfo.peInfo.NtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, dllInfo));

    // 对每个依赖dll进行加载
    while (pImDes->Characteristics != 0) // 0 for terminating null import descriptor
    {
        void **pPAddressTable = (void **)(RVAToVA(pImDes->FirstThunk, dllInfo));
        char **pPNameTable = (char **)(RVAToVA(pImDes->OriginalFirstThunk, dllInfo));
        void *fun = nullptr;

        char *moudleName = (char *)(RVAToVA(pImDes->Name, dllInfo));
        //dll名
        string str_moudleName(moudleName);

        //判断该dll是否在需要内存加载的清单之内，是则内存加载,
        //否则为系统自带的dll，调用系统接口加载
        auto pDllInfo = loadByName(str_moudleName);
        if (pDllInfo != nullptr)
        {
            //逐函数进行导入
            while (*pPNameTable != nullptr)
            {
                //判断按序号导入还是按函数名导入
                if (IMAGE_SNAP_BY_ORDINAL32((uint32_t)(*pPNameTable)))
                {
                    // 按序号导入
                    fun = getFuntionByOrd(*pDllInfo, (uint32_t)(*pPNameTable) & 0xffff);
                }
                else
                {
                    // 按函数名导入
                    uint16_t *pHint = (uint16_t *)(RVAToVA((uint32_t)(*pPNameTable), dllInfo));
                    char *pFunctionName = (char *)(pHint + 1);
                    fun = getFuntionByName(*pDllInfo, pFunctionName);
                }

                if ((uint32_t)(fun) == (uint32_t)(*pPAddressTable))
                    break;
                *pPAddressTable = (void *)(fun);
                ++pPAddressTable;
                ++pPNameTable;
            }
        }
        else // 系统dll，调用系统的接口进行导入操作
        {
            auto hMoudle = LoadLibrary(moudleName);

            while (*pPNameTable != nullptr) // end of imports
            {
                if (IMAGE_SNAP_BY_ORDINAL32((uint32_t)(*pPNameTable)))
                {
                    // 按序号导入
                    fun = (void *)GetProcAddress(hMoudle, (char *)((uint32_t)(*pPNameTable) & 0xffff));
                }
                else
                {
                    //按函数名导入
                    uint16_t *pHint = (uint16_t *)(RVAToVA((uint32_t)(*pPNameTable), dllInfo));
                    char *pFunctionName = (char *)(pHint + 1);
                    fun = (void *)GetProcAddress(hMoudle, pFunctionName);
                }
                if ((uint32_t)(fun) == (uint32_t)(*pPAddressTable))
                    break;
                *pPAddressTable = (void *)(fun);
                ++pPAddressTable;
                ++pPNameTable;
            }
        }
        ++pImDes;
    }
}

//判断该dll是否在需要内存加载的清单之内，是则内存加载,
//否则为系统自带的dll，调用系统接口加载
MoudleInfo *Loader::loadByName(const string &name)
{
    // FIXME:出于多线程考虑，dllInfo需要加锁？
    auto lowerName = name;
    transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
    auto &dllInfo = dllMap[lowerName];

    //判断是否已经加载过
    if (dllInfo.count >= 1)
    {
        ++dllInfo.count;
        return &dllInfo;
    }
    //判断是否属于没有加载，但是为等待内存加载的情况
    else if (dllInfo.pStBuf != nullptr)
    {
        //是，则递归进行内存加载
        istream dllStream(dllInfo.pStBuf.get());
        loadfromstream(dllInfo, dllStream);
        dllInfo.count = 1;
        return &dllInfo;
    }
    else
        return nullptr;
}

void *Loader::getFuntionByName(MoudleInfo &dllInfo, const string &name)
{
    PIMAGE_EXPORT_DIRECTORY pExDir = (PIMAGE_EXPORT_DIRECTORY)(RVAToVA(dllInfo.peInfo.NtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, dllInfo));
    uint32_t *addressTable = (uint32_t *)(RVAToVA(pExDir->AddressOfFunctions, dllInfo));
    uint32_t *namePointerTable = (uint32_t *)(RVAToVA(pExDir->AddressOfNames, dllInfo));
    uint16_t *ordinalTable = (uint16_t *)(RVAToVA(pExDir->AddressOfNameOrdinals, dllInfo));

    //get ordinal
    auto namePointer = namePointerTable;
    unsigned int count = 0;

    //搜索导出名字表中是否存在对应名字的函数
    for (; count < pExDir->NumberOfNames; ++count)
    {
        if (strcmp(name.c_str(), (char *)(RVAToVA(*namePointer, dllInfo))) == 0)
            break;
        ++namePointer;
    }
    if (count >= pExDir->NumberOfNames)
        return nullptr;

    //序号表和名字表是一一对应的， 序号表中存放的内容为该函数在地址表中索引
    auto rva = (addressTable[ordinalTable[count]]);
    auto ans = (void *)(RVAToVA(rva, dllInfo));

    cout << "get function from " << dllInfo.name << " by function name" << endl
         << "\tfunction name:\t" << name << endl
         << "\tfunction address:\t" << ans << endl
         << endl;

    return ans;
}

void *Loader::getFuntionByOrd(MoudleInfo &dllInfo, unsigned int ord)
{
    PIMAGE_EXPORT_DIRECTORY pExDir = (PIMAGE_EXPORT_DIRECTORY)(RVAToVA(dllInfo.peInfo.NtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, dllInfo));
    uint32_t *addressTable = (uint32_t *)(RVAToVA(pExDir->AddressOfFunctions, dllInfo));

    unsigned int ordInA = ord - pExDir->Base; // ordinal table中存储的是函数在 address table中的索引
    auto ans = (void *)(RVAToVA(addressTable[ordInA], dllInfo));

    cout << "get function from " << dllInfo.name << " by ord" << endl
         << "\tfunction ord:\t" << ord << endl
         << "\tfunction address:\t" << ans << endl
         << endl;

    return ans;
}

bool Loader::runDllMain(MoudleInfo &dllInfo, DWORD dwReason, LPVOID lpReserved)
{

    typedef BOOL(__stdcall * dllMainFun)(HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved);
    // 函数地址即为AddressOfEntryPoint
    dllMainFun dllMain = (dllMainFun)RVAToVA(dllInfo.peInfo.NtHeaders.OptionalHeader.AddressOfEntryPoint, dllInfo);

    BOOL bRet = dllMain((HINSTANCE)dllInfo.base, dwReason, lpReserved);
    if (FALSE == bRet)
    {
        cout << "error with dllMain" << endl;
    }

    return bRet;
}

MoudleInfo Loader::getMoudleInfo(const string &moudleName)
{
    auto name = moudleName;
    // 转换为小写
    transform(name.begin(), name.end(), name.begin(), ::tolower);
    return dllMap[name];
}

void Loader::unloadMoudle(MoudleInfo &dllInfo)
{

    cout << "unloading moudle:\t" << dllInfo.name << endl;
    cout << "\tcurrent count:\t" << dllInfo.count << endl;

    // FIXME:出于多线程考虑，dllInfo需要加锁？

    //判断count值
    if (dllInfo.count > 1)
    {
        cout << "count = count -1" << endl;
        --dllInfo.count;
    }
    else if (dllInfo.count == 1)
    {
        --dllInfo.count;
        runDllMain(dllInfo, DLL_PROCESS_DETACH, NULL);
        VirtualFree(dllInfo.base, 0, MEM_RELEASE);
        cout << "moudle unloaded" << endl;
    }
    else
        dllInfo.count = 0;
    cout << endl;
}
