"""
homeNetwork.py
HN
一个通信：与SN间的通信
"""
import socket
import sys
import pickle
import crypto
import datetime

class HomeNetwork():
    def __init__(self, k, supi, sqn_hn, port):
        self.k = k
        self.supi = supi
        self.sqn_hn = sqn_hn
        self.port = port
        # 建立自己的端口，等待SN连接
        try:
            self.sckt_hn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # 防止socket server重启后端口被占用（socket.error: [Errno 98] Address already in use）
            self.sckt_hn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sckt_hn.bind(('127.0.0.1', port))
            self.sckt_hn.listen(10)
        except socket.error as msg:
            print(msg)
            sys.exit(1)
        print("\033[1;32m", datetime.datetime.now().strftime("%F %T"), "\033[0m", " [等待sn连接...]")

    
    def connectSN(self):
        # 接收suci, sname
        conn, addr = self.sckt_hn.accept()
        suci, sname = pickle.loads(conn.recv(1024))
        print("\033[1;32m", datetime.datetime.now().strftime("%F %T"), "\033[0m", f" [接收suci, sname] suci: {suci}, sname: {sname}")
        # 从suci得到supi
        supi = self.getSUPI(suci)
        # 开始认证
        # 发送R, AUTN, HXRES*, K_SEAF(计算)
        r, autn, hxres_star, k_seaf = self.authentication_challenge()
        conn.send(pickle.dumps((r, autn, hxres_star, k_seaf)))
        print("\033[1;32m", datetime.datetime.now().strftime("%F %T"), "\033[0m", f" [发送R, AUTN, HXRES*, K_SEAF] R: {r}, \nAUTN: {autn}, \nHXRES*: {hxres_star}, \nK_SEAF: {k_seaf}")
        # 接收
        try:
            package = pickle.loads(conn.recv(1024))
        except EOFError:
            print("\033[1;31m", datetime.datetime.now().strftime("%F %T"), "\033[0m", " [中断连接]")
            conn.close()
            return
        print("\033[1;32m", datetime.datetime.now().strftime("%F %T"), "\033[0m", f" [从sub接收到信息] package: (message, content), message: {package[0]}")
        # 判断
        ## 若为RES*, suci
        if package[0] == 'RES*':
            res_star = package[1]
            print("\033[1;32m", datetime.datetime.now().strftime("%F %T"), "\033[0m", f" ['RES*'] RES*: {res_star}")
            ### 判断 RES* == HXRES*
            if res_star != self.xres_star:
                print("\033[1;31m", datetime.datetime.now().strftime("%F %T"), "\033[0m", f" [RES* != HXRES*] Abort")
                sys.exit(1)
            else:
                #### 向SN发送supi
                conn.send(pickle.dumps(supi))
                print("\033[1;32m", datetime.datetime.now().strftime("%F %T"), "\033[0m", f" [向SN发送supi] supi: {supi}")
        ## 若为'Sync_Failure', AUTS, R, suci
        elif package[0] == 'Sync_Failure':
            auts = package[1]
            r = package[2]
            print("\033[1;31m", datetime.datetime.now().strftime("%F %T"), "\033[0m", f" ['Sync_Failure'] AUTS: {auts}, \nR: {r}")
            ### 若 MACS == MAC
            i, xsqn_ue = self.verify(self.k, r, auts)
            if i:
                print("\033[1;31m", datetime.datetime.now().strftime("%F %T"), "\033[0m", f" ['MACS == MAC']")
                #### 重同步，sqn_hn = sqn_ue + 1
                self.sqn_hn = xsqn_ue + 1
                print("\033[1;31m", datetime.datetime.now().strftime("%F %T"), "\033[0m", f" [重同步] sqn_hn: {self.sqn_hn}")
        conn.close()
        
    
    def getSUPI(self, suci):
        if suci == "supi":
            return self.supi

    def authentication_challenge(self):
        r = crypto.getRandom(256)
        bsqn_hn = self.sqn_hn.to_bytes(256, byteorder='little')
        self.mac = crypto.fun1(self.k, sqn_hn, r)
        print("\033[1;32m", datetime.datetime.now().strftime("%F %T"), "\033[0m", f" [self.mac] self.mac = {self.mac}")
        ak = crypto.fun5(self.k, r)
        conc = crypto.getXOR(bsqn_hn, ak)
        autn = (conc, self.mac)
        self.xres_star = crypto.challenge(self.k, r, "sname_100")
        hxres_star = crypto.getsha256(r, self.xres_star)
        k_seaf = crypto.keySeed(self.k, r, sqn_hn, "sname_100")
        self.sqn_hn += 1
        return r, autn, hxres_star, k_seaf

    def verify(self, k, r, auts):
        conc_star = auts[0]
        macs = auts[1]
        xak_star = crypto.fun5(k, r)
        bxsqn_ue = crypto.getXOR(xak_star, conc_star)
        xsqn_ue = int.from_bytes(bxsqn_ue, byteorder='little')
        print("\033[1;32m", datetime.datetime.now().strftime("%F %T"), "\033[0m", f" [得到xSQN_ue] xSQN_ue: {xsqn_ue}")
        xmacs = crypto.fun1(k, xsqn_ue, r)
        if xmacs == macs:
            print("\033[1;32m", datetime.datetime.now().strftime("%F %T"), "\033[0m", " [xMACS = MACS]")
            i = True
        else:
            i = False
        return i, xsqn_ue




if __name__ == '__main__':
    k = crypto.getKey()
    sqn_hn = 100
    hn = HomeNetwork(k, "supi", sqn_hn, 1070)
    hn.connectSN()