import time
from collections import Counter

from scapy import packet
from scapy.all import sniff
import pandas as pd
import numpy as np







def custom_action(packet):
    global info
    global df
    global count_packet
    start_time = time.time()
    found = 0
    DurFound = 0
    ACKCount = 0
    leninfo = len(info)
    current_row = 0
    key = tuple(([packet[0][1].src, packet[0][1].dst,packet[0][1].proto,packet[0][1].sport,packet[0][1].dport,packet[0][1].flags]))
    src = key[0]
    dst = key[1]
    proto = key[2]
    source_port = key[3]
    dest_port = key[4]
    flag = key[5]
    ACK = 0x10
    SYN = 0x02

    Protocol = ""
    if proto == 6:
        Protocol = "TCP"
    elif proto == 17:
        Protocol = "UDP"
    elif proto == 1:
        Protocol = "ICMP"

    sessiontime = 0
    newpack = time.time() - start_time
    for i in range(0,leninfo):
        if src == str(info[i][0]) and dst == str(info[i][1]) and str(source_port == info[i][3]) and str(dest_port == info[i][4]) and Protocol == str(info[i][6]):
            if flag.value == ACK:
                ACKCount = ACKCount + 1
            sessiontime = time.time() - start_time
            # print("new packer duration is" + str(sessiontime))
            pervious = float(info[i][5])
            sessiontime = sessiontime + pervious
            ACKCount = float(ACKCount) + float(info[i][7])
            DurFound = 1
            # print(" pervious is "+str(pervious))
            # print("Now duration is "+str(sessiontime))
            df.at[df.index[i], 'duration of flow'] = sessiontime
            info[i][5] = sessiontime
            # print("hi"+ str(df.at[df.index[i], 'duration of flow']))
            df.at[df.index[i], 'ACK_flag_count'] = ACKCount
            info[i][7] = ACKCount
            # df.drop([df.index[i]],inplace=True)
    if DurFound == 0:
        sessiontime = newpack



    # calculating the total number of packets for forward direction
    for i in range(0,leninfo):
        if src == info[i][0] and dst == info[i][1]:
            temp = int(info[i][2])
            temp = temp + 1
            info[i][2] = temp
            found = 1
            current_row = i
            df.at[df.index[i], 'number of packets in forward direction'] = temp

    if found == 0:
        if flag.value == ACK:
            ACKCount = ACKCount + 1
        info = np.vstack((info, [src,dst,1,source_port,dest_port,sessiontime,Protocol,ACKCount]))
        current_row = len(info) - 1
        data = [[src, dst, source_port, dest_port, Protocol, info[current_row][2], sessiontime,ACKCount]]
        df2 = pd.DataFrame(data=data, columns=['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol',
                                               'number of packets in forward direction', 'duration of flow','ACK_flag_count'])
        df = df.append(df2, ignore_index=True)


    df.to_csv('traffic.csv', sep=',')



## Setup sniff, filtering for IP traffic

df = pd.DataFrame(columns=['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol','number of packets in forward direction','duration of flow','ACK_flag_count'])
count_packet = 0
info = np.zeros((count_packet, 8))
sniff(filter="ip", prn=custom_action)

