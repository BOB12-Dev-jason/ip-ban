#! /usr/bin/python3
import os
import re
import subprocess

filepath = "/var/log/auth.log"
failNum = {}  # {ip주소: 실패 횟수}


def ban():
    with subprocess.Popen(["tail", "-f", filepath], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as auth_process:
        for line in auth_process.stdout:
            if "Failed password" in line:
                ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)
                if ip_match:
                    ip_address = ip_match.group()
                    failNum[ip_address] = failNum.get(ip_address, 0) + 1
                    print("login fail detected: %s attempt: %d" % (ip_address, failNum[ip_address]))
                    if failNum[ip_address] >= 5:
                        print("%s 주소를 차단했습니다." % ip_address)
                        os.system("iptables -A INPUT -s %s -j DROP" % ip_address)


if __name__ == '__main__':
    ban()



# 5회이상 접속 실패 시 iptables 정책을 통해 해당 ip의 접속을 차단.

