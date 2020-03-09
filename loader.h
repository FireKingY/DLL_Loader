#include <windows.h>
#include <vector>
#include <iostream>
using namespace std;

#define BUFFER_SIZE 1024

struct PE_INFO32
{
    IMAGE_DOS_HEADER DosHeader;
    IMAGE_NT_HEADERS32 NtHeaders;
    vector<IMAGE_SECTION_HEADER> SectionHeaders;
};

class PEFile
{
public:
    void *base;
    PE_INFO32 info;

    void loadFromFile(const string &dllName);
    void close();
    DWORD RVAToVA(DWORD RVA);
    void* getFuntionByName(const string& name);
    void* getFuntionByOrd(unsigned int ord);

private:
    void initPEInfo(ifstream &pe);
    void copyDllToMem(ifstream &pe);
    void relocate();
    void fixImportTable();
};