#!/usr/bin/python3

from argparse import ArgumentParser
import socket
from threading import Thread
from time import time
import nmap
import subprocess

nm = nmap.PortScanner()

open_ports = []
opentcp = []

def prepare_args():
    parser = ArgumentParser(description="Python Based Fast Port Scanner",usage="./%(prog)s 192.168.1.1",epilog="Example - %(prog)s -s 200 -e 4000 -t 500 -V 192.168.1.1")
    parser.add_argument(metavar="IPv4",dest="ip",help="host to scan")
    parser.add_argument("-s","--start",dest="start",metavar="",type=int,help="starting port",default=1)
    parser.add_argument("-e","--end",dest="end",metavar="",type=int,help="ending port",default=1000)
    parser.add_argument("-sS","-syn-ack",dest="synack",action="store_true",help="SYN ACK Scan")
    parser.add_argument("-c","--comprehensive",dest="comp",action="store_true",help="comprehensive scan")
    parser.add_argument("-o","--output",dest="output",action="store_true",help="save output to the file: result.txt")
    parser.add_argument("-t","--threads",dest="threads",metavar="",type=int,help="threads to use", default=1000)
    args = parser.parse_args()
    return args

def prepare_ports(start:int,end:int):
    for port in range(start,end+1):
        yield port

def run_port_scanner(ip_address):
    result = subprocess.run(['./scanner.py', ip_address], capture_output=True, text=True)
    return result.stdout

def save_to_file(content, filename):
    with open(filename, 'w') as file:
        file.write(content)


def scan_port():
    while True:
        try:
            s = socket.socket()
            s.settimeout(1)
            port = next(ports)
            s.connect((arguments.ip,port))
            open_ports.append(port)
            port = next(ports)
        except (ConnectionRefusedError,socket.timeout):
            continue
        except StopIteration:
            break
            

def prepare_threads(threads:int):

    thread_list = []
    for _ in range(threads+1):
        thread_list.append(Thread(target=scan_port))

    for thread in thread_list:
        thread.start()

    for thread in thread_list:
        thread.join()
    
def comprehensive_scan(start:str,end:str):
    nm.scan(arguments.ip,f'{start}-{end}','-sS -A')

def synack_scan(start:str,end:str):
    nm.scan(arguments.ip,f'{start}-{end}','-sS')


if __name__ == "__main__":
    arguments = prepare_args()
    ports = prepare_ports(arguments.start,arguments.end)
    start_time = time()
    prepare_threads(arguments.threads)
    
    if arguments.comp:
        comprehensive_scan(arguments.start,arguments.end)
        openp = nm[arguments.ip]['tcp'].keys()
        data = nm.csv()
        lines = data.strip().split('\n')
        for line in lines[1:]:
            parts = line.split(';')
            port = parts[4]
            name = parts[5]
            state = parts[6]
            product = parts[7]
            os = parts[8]
            print("""%s/tcp     %s                 %s          %s""" % (port,name,state,product))
    elif arguments.synack:
        synack_scan(arguments.start,arguments.end)
        opentcp = nm[arguments.ip]['tcp'].keys()
        for i in opentcp:
            print("""%s/tcp      open     %s""" % (i,nm[arguments.ip]['tcp'][i]['name']))
    elif arguments.output:
        output = run_port_scanner(arguments.ip)
        save_to_file(output, 'result.txt')
    else:
        print(f"Open ports found: {open_ports}")

    end_time = time()

    print(f"Time Taken - {round(end_time-start_time,2)}")
