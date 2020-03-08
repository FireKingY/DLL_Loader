#include <fstream>
#include <cstring>
#include "loader.h"
using namespace std;

void PEFile::loadFromFile(const string &dllName)
{
    ifstream dllStream;
    dllStream.open(dllName, ios_base::binary);
    initPEInfo(dllStream);

    //allocate mem for image
    this->base = VirtualAlloc(nullptr, this->info.NtHeaders.OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    copyDllToMem(dllStream);
    relocate();

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
        void *curPos = reinterpret_cast<void *>(static_cast<uint64_t>(sectionHeader.VirtualAddress) + reinterpret_cast<uint64_t>(this->base));
        pe.seekg(sectionHeader.PointerToRawData);

        while (remainSize > BUFFER_SIZE)
        {
            pe.read(buf, BUFFER_SIZE);
            memcpy(curPos, buf, BUFFER_SIZE);
            remainSize -= BUFFER_SIZE;
            curPos = reinterpret_cast<void *>(reinterpret_cast<uint64_t>(curPos) + BUFFER_SIZE);
        }
        pe.read(buf, remainSize);
        memcpy(curPos, buf, remainSize);
    }
    return;
}

void PEFile::relocate()
{
    void *pRelocateTable = reinterpret_cast<void *>(this->info.NtHeaders.OptionalHeader.DataDirectory[5].VirtualAddress + reinterpret_cast<uint64_t>(this->base));
    void *pRelocateTableEnd = reinterpret_cast<void *>(reinterpret_cast<uint64_t>(pRelocateTable) + this->info.NtHeaders.OptionalHeader.DataDirectory[5].Size);

    void *curTablePos = pRelocateTable;
    while (curTablePos < pRelocateTableEnd)
    {
        PIMAGE_BASE_RELOCATION rel = static_cast<PIMAGE_BASE_RELOCATION>(curTablePos);
        uint16_t *offsets_start = reinterpret_cast<uint16_t *>(reinterpret_cast<uint64_t>(rel) + sizeof(*rel));
        uint16_t *offset = offsets_start;
        for (; reinterpret_cast<uint64_t>(offset) - reinterpret_cast<uint64_t>(offsets_start) < rel->SizeOfBlock - sizeof(*rel);
             offset = reinterpret_cast<uint16_t *>(reinterpret_cast<uint64_t>(offset) + sizeof(uint16_t)))
        {
            if ((*offset & 0xf000) != 0x3000)
                continue;
            void **pPData = reinterpret_cast<void **>(reinterpret_cast<uint64_t>(this->base) + static_cast<uint64_t>(rel->VirtualAddress) + ((*offset) & 0x0fff));
            *pPData = reinterpret_cast<void *>(reinterpret_cast<uint64_t>(*pPData) + reinterpret_cast<uint64_t>(this->base) - this->info.NtHeaders.OptionalHeader.ImageBase);
        }
        curTablePos = reinterpret_cast<void *>(reinterpret_cast<uint64_t>(curTablePos) + rel->SizeOfBlock);
    }
}

// void fixExportTable(PEFile& pf)
// {
//     PIMAGE_EXPORT_DIRECTORY pExDir = static_cast<PIMAGE_EXPORT_DIRECTORY>(pf.info.NtHeaders.OptionalHeader.DataDirectory[0].VirtualAddress);
// }

void dlltest()
{

    auto hd = LoadLibrary("test.dll");
    if (hd == NULL)
    {
        int errCode = GetLastError();
        cout << errCode << endl;
        FreeLibrary(hd);
        return;
    }
    typedef void (*FUN)();
    FUN f = (FUN)GetProcAddress(hd, (char *)(1));
    f();
    FreeLibrary(hd);
    return;
}

int main()
{
    dlltest();
    PEFile dll;
    dll.loadFromFile("test.dll");
    dll.close();
}