//
//  CocoaAsyncSocket.h
//  CocoaAsyncSocket
//
//  Created by Derek Clarkson on 10/08/2015.
//  CocoaAsyncSocket project is in the public domain.
//

/**
 基于上述不同，UDP和TCP编程步骤也有些不同，如下：
 　　TCP编程的服务器端一般步骤是：
 　　1、创建一个socket，用函数socket()；
 　　2、设置socket属性，用函数setsockopt(); * 可选
 　　3、绑定IP地址、端口等信息到socket上，用函数bind();
 　　4、开启监听，用函数listen()；
 　　5、接收客户端上来的连接，用函数accept()；
 　　6、收发数据，用函数send()和recv()，或者read()和write();
 　　7、关闭网络连接；
 　　8、关闭监听；
 
 　　TCP编程的客户端一般步骤是：
 　　1、创建一个socket，用函数socket()；
 　　2、设置socket属性，用函数setsockopt();* 可选
 　　3、绑定IP地址、端口等信息到socket上，用函数bind();* 可选
 　　4、设置要连接的对方的IP地址和端口等属性；
 　　5、连接服务器，用函数connect()；
 　　6、收发数据，用函数send()和recv()，或者read()和write();
 　　7、关闭网络连接；
 
 　　与之对应的UDP编程步骤要简单许多，分别如下：
 　　UDP编程的服务器端一般步骤是：
 　　1、创建一个socket，用函数socket()；
 　　2、设置socket属性，用函数setsockopt();* 可选
 　　3、绑定IP地址、端口等信息到socket上，用函数bind();
 　　4、循环接收数据，用函数recvfrom();
 　　5、关闭网络连接；
 
 　　UDP编程的客户端一般步骤是：
 　　1、创建一个socket，用函数socket()；
 　　2、设置socket属性，用函数setsockopt();* 可选
 　　3、绑定IP地址、端口等信息到socket上，用函数bind();* 可选
 　　4、设置对方的IP地址和端口等属性;
 　　5、发送数据，用函数sendto();
 　　6、关闭网络连接；
 */

@import Foundation;

//! Project version number for CocoaAsyncSocket.
FOUNDATION_EXPORT double cocoaAsyncSocketVersionNumber;

//! Project version string for CocoaAsyncSocket.
FOUNDATION_EXPORT const unsigned char cocoaAsyncSocketVersionString[];

#import <CocoaAsyncSocket/GCDAsyncSocket.h>
#import <CocoaAsyncSocket/GCDAsyncUdpSocket.h>
