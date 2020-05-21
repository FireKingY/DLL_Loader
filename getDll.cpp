#include "getDll.h"

using namespace std;

#pragma comment(lib, "ws2_32.lib")

#define BUFF_SIZE 1024

PlainFile getDll(const string &address, int port)
{
    cout << "receving file" << endl;
    //初始化DLL
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    //创建套接字
    SOCKET sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

    //向服务器发起请求
    sockaddr_in sockAddr;
    memset(&sockAddr, 0, sizeof(sockAddr)); //每个字节都用0填充
    sockAddr.sin_family = PF_INET;
    sockAddr.sin_addr.s_addr = inet_addr(address.c_str());
    sockAddr.sin_port = htons(port);
    connect(sock, (SOCKADDR *)&sockAddr, sizeof(SOCKADDR));

    // string filename = "./output/recv_encrypted";
    // file.open(filename, ios::binary | ios::trunc);

    // 创建输出流
    ostream file(nullptr);
    file.rdbuf(new stringbuf);

    //接收服务器传回的数据
    char fileName[100];
    char szBuffer[BUFF_SIZE] = {0};
    int ncount;
    int nameI = 0;
    uint64_t fileSize = 0;

    while (true)
    {
        ncount = recv(sock, szBuffer, BUFF_SIZE, 0);
        if (ncount <= 0)
            break;

        int i = 0;
        for (; i < ncount; ++i)
        {
            if (szBuffer[i] != 0x03)
                fileName[nameI++] = szBuffer[i];
            else
            {
                fileName[nameI++] = 0;
                break;
            }
        }
        int remainSize = ncount - i - 1;
        if (remainSize > 0)
        {
            file.write(szBuffer + i + 1, ncount - i - 1);
            fileSize += ncount - i - 1;
        }

        if (szBuffer[i] == 0x03)
            break;
    }

    while (true)
    {
        ncount = recv(sock, szBuffer, BUFF_SIZE, 0);
        if (ncount <= 0)
            break;
        file.write(szBuffer, ncount);
        fileSize += ncount;
    }

    //关闭套接字
    closesocket(sock);

    //终止使用 DLL
    WSACleanup();

    auto ps = file.rdbuf();
    file.rdbuf(nullptr);

    cout << "file recevied:" << endl;
    cout << "\t file name:\t" << fileName << endl
         << "\t file size:\t" << fileSize << endl
         << endl;

    return PlainFile(fileName, fileSize, ps);
}
