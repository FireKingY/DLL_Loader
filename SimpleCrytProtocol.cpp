#include "SimpleCrytProtocol.h"

void SimpleCryptProtocol::reverse(char *buf, int start, int end)
{
    while (start < end)
    {
        char tmp = buf[start];
        buf[start] = buf[end];
        buf[end] = tmp;
        ++start;
        --end;
    }
}

void SimpleCryptProtocol::rotate(char *buf, int bufSize, int steps)
{
    reverse(buf, 0, steps-1);
    reverse(buf, steps, bufSize - 1);
    reverse(buf, 0, bufSize - 1);
}
void SimpleCryptProtocol::encrypt(const fs::path &filePath, ofstream &ofs)
{
    //每个文件每次加密都随机种子
    srand(std::time(nullptr));
    magicNum = rand();
    //write magicNum
    if(magicNum == 0)
        magicNum = 0x77;
    ofs.write(&magicNum, sizeof(magicNum));

    ifstream ifs;
    ifs.open(filePath, ios_base::binary);

    //write filename
    auto fileName = filePath.filename().string();
    char tmp = 0^magicNum;
    for(auto& c: fileName)
        c ^= magicNum;

    ofs.write(fileName.c_str(), fileName.length()*sizeof(char));
    ofs.write(&tmp, sizeof(char)); // end of filename


    //write filesize
    auto fileSize = (uint64_t)fs::file_size(filePath);
    ofs.write((char *)(&fileSize), sizeof(fileSize));
    //write encrypted content
    char *buf = new char[fenceSize];
    while (true)
    {
        ifs.read(buf, fenceSize);
        if (!ifs.eof())
        {
            //栅栏加密
            rotate(buf, fenceSize, movesteps);
            // (a XOR b) XOR b = a
            for (int i = 0; i < fenceSize; ++i)
                buf[i] ^= magicNum;
            ofs.write(buf, fenceSize);
        }
        else
        {
            ofs.write(buf, ifs.gcount());
            break;
        }
    }
    delete buf;
    ifs.close();
}

DecryptedFile SimpleCryptProtocol::decrypt(istream &is)
{
    is.read(&magicNum, sizeof(magicNum));

    ostream os(nullptr);
    char fileName[100];
    char *cur = fileName;
    while (true)
    {
        os.rdbuf(new stringbuf);
        is.read(cur, sizeof(char));
        *cur ^= magicNum;

        *(cur + 1) = 0;
        if (*cur == 0)
            break;
        if (is.eof())
        {
            cur[0] = 0;
            return DecryptedFile(fileName, nullptr);
        }
        ++cur;
    }

    uint64_t fileSize;
    is.read((char *)&fileSize, sizeof(fileSize));

    char *buf = new char[fenceSize];
    while (fileSize >= (unsigned int)fenceSize)
    {
        is.read(buf, fenceSize);
        fileSize -= fenceSize;

        //解密
        // (a XOR b) XOR b = a
        for (int i = 0; i < fenceSize; ++i)
            buf[i] ^= magicNum;
        rotate(buf, fenceSize, fenceSize - movesteps);

        os.write(buf, fenceSize);
    }
    is.read(buf, fileSize);
    os.write(buf, fileSize);
    auto ps = os.rdbuf();
    os.rdbuf(nullptr);
    return DecryptedFile(fileName, ps);
}
