#include <iostream>
#include <fstream>
#include <cstring>
#include "PEReader.h"
using namespace std;

PE_INFO32 getPEInfo(ifstream &pe);
void *loadDll(const string &dllName);
void freeDll(void *base);
void copyDllToMem(ifstream &pe, PE_INFO32 &pi, void *base);
void relocate(void *dll, PE_INFO32 &pi);

#define OFFSET_OF_NT_HEADER_OFFSET 0X3C
int offsetNTHeader;

int main()
{
    void *dll = loadDll("psapi.dll");
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
    FUN f = (FUN)GetProcAddress(hd, "fun");
    f();
    FreeLibrary(hd);
    return ;
}

void *loadDll(const string &dllName)
{
    ifstream dll;
    dll.open(dllName, ios_base::binary);
    PE_INFO32 dllInfo = getPEInfo(dll);

    //allocate mem for image
    void *base = VirtualAlloc(nullptr, dllInfo.NtHeaders.OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    copyDllToMem(dll, dllInfo, base);
    relocate(base, dllInfo);

    dll.close();
    return base;
}

void freeDll(void *base)
{
    VirtualFree(base, 0, MEM_RELEASE);
}

PE_INFO32 getPEInfo(ifstream &pe)
{
    PE_INFO32 pi;
    pe.seekg(0);
    pe.read(reinterpret_cast<char *>(&(pi.DosHeader)), sizeof(pi.DosHeader)); //read dosHeader
    pe.seekg(pi.DosHeader.e_lfanew);                                          //locate ntHeader
    pe.read((char *)(&(pi.NtHeaders)), sizeof(pi.NtHeaders));                 // read ntHeader

    IMAGE_SECTION_HEADER sectionHeader;
    for (int i = 0; i < pi.NtHeaders.FileHeader.NumberOfSections; ++i) // read sectionHeaders
    {
        pe.read(reinterpret_cast<char *>(&sectionHeader), sizeof(sectionHeader));
        pi.SectionHeaders.push_back(sectionHeader);
    }

    return pi;
}

void copyDllToMem(ifstream &pe, PE_INFO32 &pi, void *base)
{

    // copy sections to mem
    char buf[BUFFER_SIZE];
    for (auto &sectionHeader : pi.SectionHeaders)
    {
        decltype(sectionHeader.Misc.VirtualSize) remainSize = sectionHeader.Misc.VirtualSize;
        void *curPos = reinterpret_cast<void *>(static_cast<uint64_t>(sectionHeader.VirtualAddress) + reinterpret_cast<uint64_t>(base));
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

void relocate(void *dllBase, PE_INFO32 &pi)
{
    void *pRelocateTable = reinterpret_cast<void *>(pi.NtHeaders.OptionalHeader.DataDirectory[5].VirtualAddress + reinterpret_cast<uint64_t>(dllBase));
    void *pRelocateTableEnd = reinterpret_cast<void *>(reinterpret_cast<uint64_t>(pRelocateTable) + pi.NtHeaders.OptionalHeader.DataDirectory[5].Size);

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
            void** pPData = reinterpret_cast<void**>(reinterpret_cast<uint64_t>(dllBase) + static_cast<uint64_t>(rel->VirtualAddress) + ((*offset) & 0x0fff));
            *pPData = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(*pPData) + reinterpret_cast<uint64_t>(dllBase) - pi.NtHeaders.OptionalHeader.ImageBase);
        }
        curTablePos = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(curTablePos) + rel->SizeOfBlock);

    }
}