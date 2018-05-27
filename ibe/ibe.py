#! /usr/bin/env python
import os
import string
import random
import SocketServer
from hashlib import sha256
from Crypto.Util.number import *
from libnum import jacobi # https://github.com/hellman/libnum (thanks to hellman for jacobi implementation)
from flag import FLAG

class Task(SocketServer.BaseRequestHandler):
    def proof_of_work(self):
        proof = ''.join([random.choice(string.ascii_letters+string.digits) for _ in xrange(20)])
        digest = sha256(proof).hexdigest()
        self.request.send("sha256(XXXX+%s) == %s\n" % (proof[4:],digest))
        self.request.send('Give me XXXX:')
        x = self.request.recv(10)
        x = x.strip()
        if len(x) != 4 or sha256(x+proof[4:]).hexdigest() != digest: 
            return False
        return True

    def handle(self):
        if not self.proof_of_work():
            return
        self.request.settimeout(600)
        req = self.request
        req.sendall('Can you recover the secret sent towards Alice?\nIt could be hard but we have an oracle for you\n')
        self.secret = os.urandom(16)
        self.count = 0
        self.reset()
        while True:
            self.count += 1
            if self.count > 8192:
                self.request.sendall('Do not bruteforce plz lol\n')
                break
            req.sendall('1. get message\n2. reset\n3. fast reset\n4. get oracle\n5. guess secret\n')
            req.sendall('> ')
            try:
                opt = int(req.recv(10))
                if opt==1:
                    self.get_msg()
                elif opt==2:
                    self.reset()
                elif opt==3:
                    self.reset_fast()
                elif opt==4:
                    self.get_oracle()
                elif opt==5:
                    self.guess()
                    break
                else:
                    break
            except:
                break
        req.close()

    def get_p(self):
        p = getStrongPrime(2048)
        while p%4 != 3:
            p = getStrongPrime(2048)
        return p
    
    def setup(self):
        p = self.get_p()
        q = self.get_p()
        return p, q

    def get_pubkey(self, n, id):
        seed = sha256(id).digest()
        cand = ''
        for i in range(16):
            cand += seed
            seed = sha256(seed).digest()
        cand = int(cand.encode('hex'), 16) % n
        while jacobi(cand,n) != 1:
            cand = (cand+1) % n
        return cand
    
    def get_rand(self, m, n):
        cand = getRandomRange(0, n, os.urandom)
        while jacobi(cand,n) != m:
            cand = (cand+1) % n
        return cand
    
    def encrypt(self, m, a, n):
        t1 = self.get_rand(m, n)
        t2 = self.get_rand(m, n)
        t1i = inverse(t1, n)
        t2i = inverse(t2, n)
        c1 = (t1+a*t1i) % n
        c2 = (t2-a*t2i) % n
        return c1, c2
    
    def get_msg(self):
        if not isPrime(self.p) or not isPrime(self.q):
            return
        self.n = self.p * self.q
        a = self.get_pubkey(self.n, 'Alice')
        self.secret = os.urandom(16)
        bits = bin(bytes_to_long(self.secret))[2:]
        bits = bits.rjust(128,'0')
        for i in range(128):
            if bits[i]=='1':
                m=1
            else:
                m=-1
            c1, c2 = self.encrypt(m, a, self.n)
            self.request.sendall('%d %d\n' % (c1, c2))
    
    def reset(self):
        self.p, self.q = self.setup()
        n = self.p * self.q
        self.request.sendall('--- setup completed ---\n')
        self.request.sendall('n: %s\n' % str(n))

    def reset_fast(self):
        self.request.sendall('This is for debug only. Do you want to continue? [Y/n] ')
        res = self.request.recv(10)
        if res[0]=='Y':
            self.p += 4
            self.q += 4

    def get_oracle(self):
        self.request.sendall('number: ')
        a = self.request.recv(2050)
        a = int(a)
        self.request.sendall("%d %d\n" % (jacobi(a,self.p), jacobi(a,self.q)))

    def guess(self):   
        self.request.sendall('secret(hex): ')
        sec = self.request.recv(100)
        sec = sec.strip().decode('hex')
        if sec == self.secret:
            self.request.sendall('All right. Your flag here. %s\n' % FLAG)
        else:
            self.request.sendall('Nope\n')


class ThreadedServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass


if __name__ == '__main__':
    HOST, PORT = '0.0.0.0', 10002
    print HOST
    print PORT
    server = ThreadedServer((HOST, PORT), Task)
    server.allow_reuse_address = True
    server.serve_forever()
