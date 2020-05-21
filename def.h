#pragma once

#include <windows.h>
#include <vector>
#include <iostream>
#include <unordered_map>
#include <cstring>
#include <fstream>
#include <algorithm>
#include <locale>
#include <filesystem>
#include <sstream>
#include <string>
#include <cstdlib>
#include <ctime>

using namespace std;

#define BUFFER_SIZE 1024

struct PlainFile
{
    string fileName;
    uint64_t fileSize;
    shared_ptr<streambuf> pStBuf;
    PlainFile(char *fileName, uint64_t fileSize, shared_ptr<streambuf> pStBuf);
    PlainFile(char *fileName, uint64_t fileSize, streambuf *pStBuf);
    PlainFile();
    ~PlainFile();
};

struct PE_INFO32
{
    IMAGE_DOS_HEADER DosHeader;
    IMAGE_NT_HEADERS32 NtHeaders;
    vector<IMAGE_SECTION_HEADER> SectionHeaders;
};

struct MoudleInfo
{
    string name;
    uint32_t count;                 // FIXME:出于多线程考虑，dllInfo需要加锁？
    void *base;
    PE_INFO32 peInfo;
    shared_ptr<streambuf> pStBuf; // 当dll被解密但尚未被加载时有效，用于在被依赖时定位用
    MoudleInfo();
};