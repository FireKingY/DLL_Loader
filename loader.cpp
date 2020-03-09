#include <fstream>
#include <cstring>
#include "loader.h"
using namespace std;

DWORD PEFile::RVAToVA(DWORD RVA)
{
    return RVA + reinterpret_cast<uint32_t>(this->base);
}

void PEFile::loadFromFile(const string &dllName)
{
    ifstream dllStream;
    dllStream.open(dllName, ios_base::binary);
    initPEInfo(dllStream);

    //allocate mem for image 可读可写可执行
    this->base = VirtualAlloc(nullptr, this->info.NtHeaders.OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    copyDllToMem(dllStream);
    relocate();
    fixImportTable();

    dllStream.close();
    return;
}

void PEFile::close()
{
    VirtualFree(this->base, 0, MEM_RELEASE);
}

void PEFile::initPEInfo(ifstream &dllStream)
{
    dllStream.seekg(0);
    dllStream.read(reinterpret_cast<char *>(&(this->info.DosHeader)), sizeof(this->info.DosHeader)); //read dosHeader
    dllStream.seekg(this->info.DosHeader.e_lfanew);                                                  //locate ntHeader
    dllStream.read((char *)(&(this->info.NtHeaders)), sizeof(this->info.NtHeaders));                 // read ntHeader

    IMAGE_SECTION_HEADER sectionHeader;
    for (int i = 0; i < this->info.NtHeaders.FileHeader.NumberOfSections; ++i) // read sectionHeaders
    {
        dllStream.read(reinterpret_cast<char *>(&sectionHeader), sizeof(sectionHeader));
        this->info.SectionHeaders.push_back(sectionHeader);
    }

    return;
}

void PEFile::copyDllToMem(ifstream &pe)
{

    // copy sections to mem
    char buf[BUFFER_SIZE];
    for (auto &sectionHeader : this->info.SectionHeaders)
    {
        decltype(sectionHeader.Misc.VirtualSize) remainSize = sectionHeader.SizeOfRawData;
        void *curPos = reinterpret_cast<void *>(RVAToVA(sectionHeader.VirtualAddress));
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

void PEFile::relocate()
{
    void *pRelocateTable = reinterpret_cast<void *>(RVAToVA(this->info.NtHeaders.OptionalHeader.DataDirectory[5].VirtualAddress));
    void *pRelocateTableEnd = reinterpret_cast<void *>(reinterpret_cast<uint32_t>(pRelocateTable) + this->info.NtHeaders.OptionalHeader.DataDirectory[5].Size);

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
            void **pPData = reinterpret_cast<void **>(RVAToVA(rel->VirtualAddress) + ((*offset) & 0x0fff));
            *pPData = reinterpret_cast<void *>(reinterpret_cast<uint32_t>(*pPData) + reinterpret_cast<uint32_t>(this->base) - this->info.NtHeaders.OptionalHeader.ImageBase);
        }
        curTablePos = reinterpret_cast<void *>(reinterpret_cast<uint32_t>(curTablePos) + rel->SizeOfBlock);
    }
}

void *PEFile::getFuntionByName(const string &name)
{
    static PIMAGE_EXPORT_DIRECTORY pExDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(RVAToVA(this->info.NtHeaders.OptionalHeader.DataDirectory[0].VirtualAddress));
    static uint32_t *addressTable = reinterpret_cast<uint32_t *>(RVAToVA(pExDir->AddressOfFunctions));
    static uint32_t *namePointerTable = reinterpret_cast<uint32_t *>(RVAToVA(pExDir->AddressOfNames));
    static uint16_t *ordinalTable = reinterpret_cast<uint16_t *>(RVAToVA(pExDir->AddressOfNameOrdinals));

    //get ordinal
    auto namePointer = namePointerTable;
    unsigned int count = 0;

    //搜索导出名字表中是否存在对应名字的函数
    for (; count < pExDir->NumberOfNames; ++count)
    {
        if (strcmp(name.c_str(), reinterpret_cast<char *>(RVAToVA(*namePointer))) == 0)
            break;
        ++namePointer;
    }
    if (count >= pExDir->NumberOfNames)
        return nullptr;

    auto rva = (addressTable[ordinalTable[count]]); //序号表和名字表是一一对应的， 序号表中存放的内容为该函数在地址表中索引
    return reinterpret_cast<void *>(RVAToVA(rva));
}
void *PEFile::getFuntionByOrd(unsigned int ord)
{
    static PIMAGE_EXPORT_DIRECTORY pExDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(RVAToVA(this->info.NtHeaders.OptionalHeader.DataDirectory[0].VirtualAddress));
    static uint32_t *addressTable = reinterpret_cast<uint32_t *>(RVAToVA(pExDir->AddressOfFunctions));

    ord -= pExDir->Base; // ordinal table中存储的是函数在 address table中的索引
    return reinterpret_cast<void *>(RVAToVA(addressTable[ord]));
}

void PEFile::fixImportTable()
{
    PIMAGE_IMPORT_DESCRIPTOR pImDes = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(RVAToVA(this->info.NtHeaders.OptionalHeader.DataDirectory[1].VirtualAddress));

    while(pImDes->Characteristics != 0) // 0 for terminating null import descriptor
    {
        char* moudleName = reinterpret_cast<char*>(RVAToVA(pImDes->Name));
        auto hMoudle = LoadLibrary(moudleName);
        char** pPAddressTable = reinterpret_cast<char**>(RVAToVA(pImDes->FirstThunk));
        while(*pPAddressTable != nullptr)
        {
            uint16_t* pHint = reinterpret_cast<uint16_t*>(RVAToVA(reinterpret_cast<uint32_t>(*pPAddressTable)));
            char* pFunctionName = reinterpret_cast<char*>(pHint + 1);
            auto fun = GetProcAddress(hMoudle, pFunctionName);
            *pPAddressTable = reinterpret_cast<char*>(fun);
            ++pPAddressTable;
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

int main()
{
    // dlltest();
    PEFile dll;
    dll.loadFromFile("C:\\Users\\Administrator\\source\\repos\\testDlll\\Release\\testDlll.dll");
    typedef const char *(*FUN)(int a, int b);
     FUN fun = reinterpret_cast<FUN>(dll.getFuntionByName("sub"));
   //FUN fun = reinterpret_cast<FUN>(dll.getFuntionByOrd(4));
    if (fun != nullptr)
        cout << fun(22,33) << endl;
    dll.close();
}