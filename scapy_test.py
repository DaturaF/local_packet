#! /usr/bin/env python
#coding:utf-8
from scapy.all import *
import time

def timestamp2time(timestamp):
    timeArray = time.localtime(timestamp)
    mytime = time.strftime("%Y-%m-%d %H:%M:%S", timeArray)
    return mytime

def pack_callback(packet):
    if "host: " in str(packet.payload).lower():
        #print "TimeStamp:%s" % packet.time                 #当前时间
        #print "Sniff-Time:%s"% timestamp2time(packet.time) #当前时间
        #print "Src-IP:%s" % packet[IP].src                 #源IP地址
        #print "Src-Port:%s" % packet[TCP].sport            #源端口
        #print "Dst-IP:%s"%packet[IP].dst                   #目标IP地址
        #print "Dst-IP:%s" % packet[TCP].dport              #目标端口
        #print "%s"%packet[TCP].payload                     #报信息
        #print "%s"%packet.summary()                        #显示数据摘要
        #print "%s"%packet.show()                           #显示数据包的状况
        print "%s --- %s:%s --> %s:%s " %(timestamp2time(packet.time),packet[IP].src,packet.sport,packet[IP].dst,packet.dport)
        print packet[TCP].payload
        #print "%s"%packet.src
        print "*******************************************************************"

sniff(filter="tcp port 80 and src host 192.168.88.3",prn=pack_callback,iface="eth0",count=0)
        # 标准格式：sniff(filter="",iface="any",prn=function,count=N)
        # filter 对scapy嗅探的数据包 指定一个 BPF（wireshark类型）的过滤器，留空嗅探所有数据包
        # iface  设置所需要嗅探的网卡，留空嗅探所有网卡
        # prn    指定嗅探到符合过滤器条件的数据包时所调用的回调函数,这个回调函数以接受到的数据包对象作为唯一的参数。
        # count  指定嗅探的数据包的个数，留空则默认为嗅探无限个

    '''
    sniff(iface="eth0",prn=lambda x:x.summary())
    sniff(iface="eth0",prn=lambda x:x.show())
    pkts = sniff(prn=lambda x:x.sprintf("{IP:%IP.src% -> %IP.dst%\n}{Raw:%Raw.load%\n}"))
    pkts = sniff(prn=lambda x:x.sprintf("{IP:%IP.dst% {ICMP:%ICMP.type%}{TCP:%TCP.dport%}}"))
    '''