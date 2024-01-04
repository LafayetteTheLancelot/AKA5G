"""
servingNetwork.py
SN
两个通信：与sub的&与HN的
"""
import socket
import sys
import pickle
import crypto
import datetime

class ServingNetwork():
    def __init__(self, sname, suci, port):
        self.sname = sname
        self.suci = suci
        self.port = port
        # 建立自己的端口，等待scb连接
        try:
            self.sckt_sn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # 防止socket server重启后端口被占用（socket.error: [Errno 98] Address already in use）
            self.sckt_sn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sckt_sn.bind(('127.0.0.1', port))
            self.sckt_sn.listen(10)
        except socket.error as msg:
            print(msg)
            sys.exit(1)
        print("\033[1;32m", datetime.datetime.now().strftime("%F %T"), "\033[0m", " [等待sub入网...]")
        
    def connectHN(self, port_hn):
        try:
            self.sckt2hn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sckt2hn.connect(('127.0.0.1', port_hn))
        except socket.error as msg:
            print(msg)
            sys.exit(1)

    def transfer(self):
        # 从sub接收suci
        conn, addr = self.sckt_sn.accept()
        suci = pickle.loads(conn.recv(1024))
        print("\033[1;32m", datetime.datetime.now().strftime("%F %T"), "\033[0m", f" [从sub接收suci] suci: {suci}")
        # 向HN发suci, sname
        self.connectHN(1070)
        self.sckt2hn.send(pickle.dumps((suci, self.sname)))
        print("\033[1;32m", datetime.datetime.now().strftime("%F %T"), "\033[0m", f" [向HN发suci, sname] suci: {suci}, sname: {self.sname}")
        # 从HN接收 R, AUTN, HXRES*, K_SEAF
        r, autn, hxres_star, k_seaf = pickle.loads(self.sckt2hn.recv(1024))
        print("\033[1;32m", datetime.datetime.now().strftime("%F %T"), "\033[0m", f" [从HN接收 R, AUTN, HXRES*, K_SEAF] R: {r}, \nAUTN: {autn}, \nHXRES*: {hxres_star}, \nK_SEAF: {k_seaf}")
        # 向sub发R, AUTN
        conn.send(pickle.dumps((r, autn)))
        print("\033[1;32m", datetime.datetime.now().strftime("%F %T"), "\033[0m", f" [向sub发R, AUTN] R: {r}, AUTN: {autn}")
        # 从sub接收到信息(要返回元组)
        package = pickle.loads(conn.recv(1024))
        print("\033[1;32m", datetime.datetime.now().strftime("%F %T"), "\033[0m", f" [从sub接收到信息] package: {package}")
        # 判断
        ## 若为'Mac_Failure'
        ### 结束
        if package[0] == 'Mac_Failure':
            print("\033[1;31m", datetime.datetime.now().strftime("%F %T"), "\033[0m", " [Mac_Failure] Abort")
        
        ## 若为'Sync_Failure', AUTS
        ### 向HN发送'Sync_Failure', AUTS, R, suci
        elif package[0] == 'Sync_Failure':
            print("\033[1;31m", datetime.datetime.now().strftime("%F %T"), "\033[0m", " [Sync_Failure]")
            auts = package[1]
            self.sckt2hn.send(pickle.dumps(('Sync_Failure', auts, r, suci)))
            print("\033[1;31m", datetime.datetime.now().strftime("%F %T"), "\033[0m", f" [向HN发送'Sync_Failure', AUTS, R, suci] AUTS: {auts}, \nR: {r}, \nsuci: {suci}")
        ## 若为RES*
        ### 判断 SHA256(<R, RES*>) == HXRES*
        elif package[0] == 'RES*':
            res_star = package[1]
            print("\033[1;32m", datetime.datetime.now().strftime("%F %T"), "\033[0m", f" [RES*] RES*: {res_star}")
            if crypto.getsha256(r, res_star) != hxres_star: #--------此处str待修改
                print("\033[1;31m", datetime.datetime.now().strftime("%F %T"), "\033[0m", " [SHA256(<R, RES*>) != HXRES*] Abort")
                sys.exit(1)
            else:
                #### 向HN发送RES*, suci
                self.sckt2hn.send(pickle.dumps(('RES*', res_star, suci)))
                print("\033[1;32m", datetime.datetime.now().strftime("%F %T"), "\033[0m", f" [向HN发送RES*, suci] RES*: {res_star}, suci: {suci}")
                #### 从HN得到supi
                supi = pickle.loads(self.sckt2hn.recv(1024))
                print("\033[1;32m", datetime.datetime.now().strftime("%F %T"), "\033[0m", f" [从HN得到supi] supi: {supi}")
        conn.close()
        self.sckt2hn.close()

        

        

if __name__ == '__main__':
    sn = ServingNetwork("sname_100", "suci", 8080)
    sn.transfer()