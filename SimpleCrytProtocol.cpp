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
    reverse(buf, 0, steps - 1);
    reverse(buf, steps, bufSize - 1);
    reverse(buf, 0, bufSize - 1);
}
void SimpleCryptProtocol::encrypt(const PlainFile &file, ofstream &ofs)
{
    cout << "\tencrypting file:\t" << file.fileName << endl;

    //每个文件每次加密都随机种子
    srand(std::time(nullptr));
    magicNum = rand();
    //write magicNum
    if (magicNum == 0)
        magicNum = 0x77;
    ofs.write(&magicNum, sizeof(magicNum));

    istream is(file.pStBuf.get());

    //write filename
    auto fileName = file.fileName;
    char tmp = 0 ^ magicNum;
    for (auto &c : fileName)
        c ^= magicNum;

    ofs.write(fileName.c_str(), fileName.length() * sizeof(char));
    ofs.write(&tmp, sizeof(char)); // end of filename

    //write filesize
    auto fileSize = file.fileSize;
    ofs.write((char *)(&fileSize), sizeof(fileSize));
    //write encrypted content
    char *buf = new char[fenceSize];
    while (true)
    {
        is.read(buf, fenceSize);
        if (!is.eof())
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
            ofs.write(buf, is.gcount());
            break;
        }
    }
    delete buf;

    cout << "\tfile encrypted"<< endl;
}

PlainFile SimpleCryptProtocol::decrypt(istream &is)
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
            return PlainFile(fileName, 0, nullptr);
        }
        ++cur;
    }

    uint64_t fileSize;
    is.read((char *)&fileSize, sizeof(fileSize));
    auto remainSize = fileSize;

    char *buf = new char[fenceSize];
    while (remainSize >= (unsigned int)fenceSize)
    {
        is.read(buf, fenceSize);
        remainSize -= fenceSize;

        //解密
        // (a XOR b) XOR b = a
        for (int i = 0; i < fenceSize; ++i)
            buf[i] ^= magicNum;
        rotate(buf, fenceSize, fenceSize - movesteps);

        os.write(buf, fenceSize);
    }
    is.read(buf, remainSize);
    os.write(buf, remainSize);
    auto ps = os.rdbuf();
    os.rdbuf(nullptr);

    cout << "file decrypted" << endl
         << "\tfile name:\t" << fileName << endl
         << "\tfile size:\t" << fileSize<< " bytes" << endl;

    return PlainFile(fileName, fileSize, ps);
}
