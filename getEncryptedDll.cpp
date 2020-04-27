#include "getEncryptedDll.h"
#include <WinSock2.h>
using namespace std;

#pragma comment(lib, "ws2_32.lib")

#define BUFF_SIZE 1024

shared_ptr<streambuf> getEncryptedDll()
{
    //初始化DLL
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    //创建套接字
    SOCKET sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

    //向服务器发起请求
    sockaddr_in sockAddr;
    memset(&sockAddr, 0, sizeof(sockAddr)); //每个字节都用0填充
    sockAddr.sin_family = PF_INET;
    sockAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    sockAddr.sin_port = htons(1234);
    connect(sock, (SOCKADDR *)&sockAddr, sizeof(SOCKADDR));

    // string filename = "./output/recv_encrypted";
    // file.open(filename, ios::binary | ios::trunc);

    // 创建输出流
    ostream file(nullptr);
    file.rdbuf(new stringbuf);

    //接收服务器传回的数据
    char szBuffer[BUFF_SIZE] = {0};
    int ncount;
    while (true)
    {
        ncount = recv(sock, szBuffer, BUFF_SIZE, 0);
        if (ncount <= 0)
            break;
        file.write(szBuffer, ncount);
    }

    //关闭套接字
    closesocket(sock);

    //终止使用 DLL
    WSACleanup();

    auto ps = file.rdbuf();
    file.rdbuf(nullptr);

    return shared_ptr<streambuf>(ps);
}
