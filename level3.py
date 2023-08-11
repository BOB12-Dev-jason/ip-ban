#! /usr/bin/python3
import os
import re
import subprocess
import time
import threading

filepath = "/var/log/auth.log"
fail_ips = {}  # {ip주소: (실패 횟수,실패 시간)}
banned_ips = {}  # {ip주소: 실패시간}
ban_lock = threading.Lock()


def ban(ip, bantime):
    print("%s 주소를 차단했습니다." % ip)
    os.system("iptables -A INPUT -s %s -j DROP" % ip)
    banned_ips[ip] = bantime+300


def unban(ip):
    print("%s 주소의 차단을 해제했습니다." % ip)
    os.system("iptables -D INPUT -s %s -j DROP" % ip)
    del banned_ips[ip]


def unban_thread():
    while True:
        print("unban thread called")
        now = time.time()
        with ban_lock:
            for ip_address, ban_end_time in list(banned_ips.items()):
                print("banned ip: %s" % ip_address)
                if now >= ban_end_time:
                    unban(ip_address)
        time.sleep(60)


def check_log():
    with subprocess.Popen(["tail", "-f", filepath], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as auth_process:
        for line in auth_process.stdout:
            if "Failed password" in line:
                ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)
                # ip주소 추출
                if ip_match:
                    ip_address = ip_match.group()
                    cur_time = time.time()
                    if ip_address in fail_ips:  # 이전에 실패한 적 있는 ip일 경우
                        fail_count, fail_time = fail_ips[ip_address]
                        if cur_time - fail_time <= 60:  # 최근 1분 내에 실패한 경우 count+1
                            fail_count += 1
                            fail_ips[ip_address] = fail_count, fail_time
                            print("Login fail detected: %s Attempt: %d" % (ip_address, fail_count))
                            if fail_count >= 5:
                                ban(ip_address, cur_time)
                        else:  # 1분 이후면 횟수 초기화 (첫 접속 실패로 간주)
                            print("Login fail detected: %s Attempt: %d" % (ip_address, 1))
                            fail_ips[ip_address] = (1, cur_time)
                    else:  # 처음 접속 실패인 경우
                        print("Login fail detected: %s Attempt: %d" % (ip_address, 1))
                        fail_ips[ip_address] = (1, cur_time)


if __name__ == '__main__':
    threading.Thread(target=unban_thread, daemon=True).start()
    check_log()


# 5회이상 접속 실패 시 iptables 정책을 통해 해당 ip의 접속을 차단.

