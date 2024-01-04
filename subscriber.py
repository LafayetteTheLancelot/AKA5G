"""
subscriber.py
用户
一个通信：与SN的
"""
import socket
import sys
import pickle
import crypto
import datetime

class Subscriber():
    def __init__(self, k, supi, sqn_ue, sname,port_sn):
        self.k = k
        self.supi = supi
        self.sqn_ue = sqn_ue
        self.sname = sname
        self.port_sn = port_sn
        # 入网，连接SN
        try:
            self.sckt2sn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sckt2sn.connect(('127.0.0.1', port_sn))
            print("\033[1;32m", datetime.datetime.now().strftime("%F %T"), "\033[0m", f" [入网，连接SN]")
        except socket.error as msg:
            print(msg)
            sys.exit(1)
    
    def connectSN(self, suci):
        # 初始化，发送suci
        suci = self.getSUCI()
        self.sckt2sn.send(pickle.dumps(suci))
        print("\033[1;32m", datetime.datetime.now().strftime("%F %T"), "\033[0m", f" [初始化，发送suci] suci: {suci}")
        # 接收R, AUTN
        r, autn = pickle.loads(self.sckt2sn.recv(1024))
        print("\033[1;32m", datetime.datetime.now().strftime("%F %T"), "\033[0m", f" [接收R, AUTN] R: {r}, \nAUTN: {autn}")
        # 验证(计算)
        i, ii, xsqn_hn = self.verify(self.k, r, autn)
        print("\033[1;32m", datetime.datetime.now().strftime("%F %T"), "\033[0m", f" [验证] i: {i}, ii: {ii}")
        # 判断
        ## if i and ii:
        ### 发送RES*(计算)
        if i and ii:
            self.sqn_ue = xsqn_hn
            res_star = self.getRES_star(self.k, r, self.sname)
            self.sckt2sn.send(pickle.dumps(('RES*', res_star)))
            print("\033[1;32m", datetime.datetime.now().strftime("%F %T"), "\033[0m", f" [发送RES*] RES*: {res_star}")
        ## if i and !ii:
        ### 发送'Sync_Failure', AUTS(计算)
        elif i and not ii:
            auts = self.getAUTS(self.k, self.sqn_ue, r)
            self.sckt2sn.send(pickle.dumps(('Sync_Failure', auts)))
            print("\033[1;31m", datetime.datetime.now().strftime("%F %T"), "\033[0m", f" [发送'Sync_Failure', AUTS] AUTS: {auts}")
        ## if !i:
        ### 发送'Mac_Failure'
        elif not i:
            self.sckt2sn.send(pickle.dumps(('Mac_Failure', )))
            print("\033[1;31m", datetime.datetime.now().strftime("%F %T"), "\033[0m", f" [发送'Mac_Failure']")
        self.sckt2sn.close()
    
    def getSUCI(self):
        suci = self.supi
        return suci

    def verify(self, k, r, autn):
        xconc = autn[0]
        xmac = autn[1]
        ak = crypto.fun5(k, r)
        bxsqn_hn = crypto.getXOR(ak, xconc)
        xsqn_hn = int.from_bytes(bxsqn_hn, byteorder='little')
        print("\033[1;32m", datetime.datetime.now().strftime("%F %T"), "\033[0m", f" [得到xSQN_hn] xSQN_hn: {xsqn_hn}")
        mac = crypto.fun1(k, xsqn_hn, r)
        if xmac == mac:
            print("\033[1;32m", datetime.datetime.now().strftime("%F %T"), "\033[0m", " [xMAC = MAC]")
            i = True
        else:
            i = False
        if self.sqn_ue < xsqn_hn:
            print("\033[1;32m", datetime.datetime.now().strftime("%F %T"), "\033[0m", " [SQN_ne < xSQN_hn]")
            ii = True
        else:
            ii = False
        return i, ii, xsqn_hn
    
    def getRES_star(self, k, r, sname):
        return crypto.challenge(k, r, sname)

    def getAUTS(self, k, sqn_ue, r):
        macs = crypto.fun1_star(k, sqn_ue, r)
        ak_star = crypto.fun5_star(k, r)
        bsqn_ue = sqn_ue.to_bytes(256, byteorder='little')
        conc_star = crypto.getXOR(bsqn_ue, ak_star)
        return (conc_star, macs)

if __name__ == '__main__':
    k = crypto.getKey()
    sqn_ue = 99
    scb = Subscriber(k, "supi", sqn_ue, "sname_100", 8080)
    scb.connectSN("suci")
