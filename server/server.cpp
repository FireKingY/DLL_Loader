#include <cstring>
#include <iostream>
#include <fstream>
#include <experimental/filesystem>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

using namespace std;

#define BUFF_SIZE 1024

int main()
{
    //创建套接字
    int serv_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    //将套接字和IP、端口绑定
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));           //每个字节都用0填充
    serv_addr.sin_family = AF_INET;                     //使用IPv4地址
    serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1"); //具体的IP地址
    serv_addr.sin_port = htons(1234);                   //端口
    bind(serv_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr));

    //进入监听状态，等待用户发起请求
    listen(serv_sock, 20);

    //向客户端发送数据
    while (true)
    {
        //接收客户端请求
        struct sockaddr_in clnt_addr;
        socklen_t clnt_addr_size = sizeof(clnt_addr);
        int clnt_sock = accept(serv_sock, (struct sockaddr *)&clnt_addr, &clnt_addr_size);

        cout << inet_ntoa(clnt_addr.sin_addr) << endl;

        char buffer[BUFF_SIZE] = {0};
        // open file
        string filename = "InfoReader.dll";
        string filePath = "./" + filename;
        if (!(experimental::filesystem::exists(filePath)))
        {
            cout << "file does not exist" << endl;
            //关闭输出流，阻塞，等待连接关闭
            shutdown(clnt_sock, SHUT_WR);
            read(clnt_sock, buffer, BUFF_SIZE);
            close(clnt_sock);
            close(serv_sock);
            return -1;
        }
        else
        {
            cout << "file exists" << endl;
            ifstream file;
            file.open(filePath, ios_base::binary);
            write(clnt_sock, filename.c_str(), filename.length());
            char tmp = 0x03;
            write(clnt_sock, &tmp, 1); //结束标志
            while(true)
            {
                file.read(buffer, BUFF_SIZE);
                if(!file.eof())
                {
                    write(clnt_sock, buffer, BUFF_SIZE);
                }
                else
                {

                    write(clnt_sock, buffer, file.gcount());
                    break;
                }
            }
            file.close();
        }

        //关闭输出流，阻塞，等待连接关闭
        shutdown(clnt_sock, SHUT_WR);
        read(clnt_sock, buffer, BUFF_SIZE);
        close(clnt_sock);
    }

    //关闭套接字
    close(serv_sock);

    return 0;
}
