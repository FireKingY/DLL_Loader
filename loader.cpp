#include <iostream>
#include <fstream>
#include <cstring>
#include "PEReader.h"
using namespace std;

PE_INFO32 getPEInfo(ifstream &pe);
PEFile loadDll(const string &dllName);
void freeDll(PEFile& pf);
void copyDllToMem(ifstream &pe, PEFile& pf);
void relocate(PEFile& pf);
void dlltest();

#define OFFSET_OF_NT_HEADER_OFFSET 0X3C
int offsetNTHeader;

int main()
{
   dlltest();
    auto dll = loadDll("test.dll");
    freeDll(dll);
}

void dlltest()
{

    auto hd = LoadLibrary("test.dll");
    if(hd == NULL)
    {
        int errCode = GetLastError();
        cout << errCode << endl;
        FreeLibrary(hd);
        return ;
    }
    typedef void(*FUN)();
    FUN f = (FUN)GetProcAddress(hd, (char*)(1));
    f();
    FreeLibrary(hd);
    return ;
}

PEFile loadDll(const string &dllName)
{
    PEFile pf;

    ifstream dllStream;
    dllStream.open(dllName, ios_base::binary);
    pf.info = getPEInfo(dllStream);

    //allocate mem for image
    pf.base = VirtualAlloc(nullptr, pf.info.NtHeaders.OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    copyDllToMem(dllStream, pf);
    relocate(pf);

    dllStream.close();
    return pf;
}

void freeDll(PEFile& pf)
{
    VirtualFree(pf.base, 0, MEM_RELEASE);
}

PE_INFO32 getPEInfo(ifstream &dllStream)
{
    PE_INFO32 pi;
    dllStream.seekg(0);
    dllStream.read(reinterpret_cast<char *>(&(pi.DosHeader)), sizeof(pi.DosHeader)); //read dosHeader
    dllStream.seekg(pi.DosHeader.e_lfanew);                                          //locate ntHeader
    dllStream.read((char *)(&(pi.NtHeaders)), sizeof(pi.NtHeaders));                 // read ntHeader

    IMAGE_SECTION_HEADER sectionHeader;
    for (int i = 0; i < pi.NtHeaders.FileHeader.NumberOfSections; ++i) // read sectionHeaders
    {
        dllStream.read(reinterpret_cast<char *>(&sectionHeader), sizeof(sectionHeader));
        pi.SectionHeaders.push_back(sectionHeader);
    }

    return pi;
}

void copyDllToMem(ifstream &pe, PEFile& pf)
{

    // copy sections to mem
    char buf[BUFFER_SIZE];
    for (auto &sectionHeader : pf.info.SectionHeaders)
    {
        decltype(sectionHeader.Misc.VirtualSize) remainSize = sectionHeader.SizeOfRawData;
        void *curPos = reinterpret_cast<void *>(static_cast<uint64_t>(sectionHeader.VirtualAddress) + reinterpret_cast<uint64_t>(pf.base));
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

void relocate(PEFile& pf)
{
    void *pRelocateTable = reinterpret_cast<void *>(pf.info.NtHeaders.OptionalHeader.DataDirectory[5].VirtualAddress + reinterpret_cast<uint64_t>(pf.base));
    void *pRelocateTableEnd = reinterpret_cast<void *>(reinterpret_cast<uint64_t>(pRelocateTable) + pf.info.NtHeaders.OptionalHeader.DataDirectory[5].Size);

    void *curTablePos = pRelocateTable;
    while (curTablePos < pRelocateTableEnd)
    {
        PIMAGE_BASE_RELOCATION rel = static_cast<PIMAGE_BASE_RELOCATION>(curTablePos);
        uint16_t *offsets_start = reinterpret_cast<uint16_t *>(reinterpret_cast<uint64_t>(rel) + sizeof(*rel));
        uint16_t *offset = offsets_start;
        for (; reinterpret_cast<uint64_t>(offset) - reinterpret_cast<uint64_t>(offsets_start) < rel->SizeOfBlock - sizeof(*rel);
             offset = reinterpret_cast<uint16_t *>(reinterpret_cast<uint64_t>(offset) + sizeof(uint16_t)))
        {
            if((*offset & 0xf000) != 0x3000)
                continue;
            void** pPData = reinterpret_cast<void**>(reinterpret_cast<uint64_t>(pf.base) + static_cast<uint64_t>(rel->VirtualAddress) + ((*offset) & 0x0fff));
            *pPData = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(*pPData) + reinterpret_cast<uint64_t>(pf.base) - pf.info.NtHeaders.OptionalHeader.ImageBase);
        }
        curTablePos = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(curTablePos) + rel->SizeOfBlock);

    }
}