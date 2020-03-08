#include <windows.h>
#include <vector>
using namespace std;

#define BUFFER_SIZE 1024

struct PE_INFO32
{
    IMAGE_DOS_HEADER DosHeader;
    IMAGE_NT_HEADERS32 NtHeaders;
    vector<IMAGE_SECTION_HEADER> SectionHeaders;
};

struct PEFile
{
    void* base;
    PE_INFO32 info;
};