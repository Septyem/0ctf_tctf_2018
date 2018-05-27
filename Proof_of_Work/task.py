import os
from struct import pack, unpack
from math import sin
import SocketServer
from flag import FLAG

def leftrotate(x,r):
    x&=0xffffffff
    return ((x<<r)|(x>>(32-r)))&0xffffffff

def notmd5(s):
    r = [6, 10, 15, 21,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22, 5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  4, 11, 16, 23]
    k = []
    for i in range(32):
        k.append(int(abs(sin(i + 1)) * 2**32))
       
    assert len(s)%64 == 0 # I'm too lazy to add padding myself
    '''
    pad = pack('Q', 8*len(s))
    s += '\x80'
    while len(s) % 64 != 56:
        s += '\x00'
    s += pad
    '''

    h0 = 0xe8b5b857
    h1 = 0xc99e4547
    h2 = 0x579f7a90
    h3 = 0x1fff0731

    for i in range(len(s)/64):
        w = []
        for j in range(16):
            w.append(unpack('I', s[i*64+j*4:i*64+j*4+4])[0])
        a = h0
        b = h1
        c = h2
        d = h3
        for i in range(32):
            if i<4:
                f = c ^ (b | (~d))
            elif i<16:
                f = (b & c) | ((~b) & d)
            elif i<28:
                f = (b & d) | ((~d) & c)
            else:
                f = b ^ c ^ d

            if i<16:
                g = i
            else:
                g = (5*i+1)%16

            tmp = d
            d = c
            c = b
            b = (leftrotate(a+f+k[i]+w[g], r[i])+b) & 0xffffffff
            a = tmp
        h0 = (h0+a) & 0xffffffff
        h1 = (h1+b) & 0xffffffff
        h2 = (h2+c) & 0xffffffff
        h3 = (h3+d) & 0xffffffff

    return pack('I',h0)+pack('I',h1)+pack('I',h2)+pack('I',h3)

def xor(a,b):
    return ''.join(map(lambda (x,y):chr(ord(x)^ord(y)), zip(a,b)))

D = 16 # I'm afraid of DoS so make it as large as possible

class Task(SocketServer.BaseRequestHandler):
    def proof_of_work(self):
        prefix = os.urandom(4)
        self.request.send(prefix.encode('base64'))
        x = self.request.recv(200).strip()
        if x.find(':')==-1:
            return False
        a, b = x.split(':')
        a = a.decode('base64')
        b = b.decode('base64')
        if a!=b and len(prefix+a)==64 and len(prefix+b)==64 and xor(notmd5(prefix+a), notmd5(prefix+b))[:D] == '\x00'*D:
            return True
        else:
            return False

    def handle(self):
        self.request.settimeout(60)
        if not self.proof_of_work():
            return
        req = self.request
        succ = True
        '''
        Do some task here and set succ as False if failed
        '''
        if succ:
            req.sendall("Good job and your flag here. %s\n" % FLAG)
        else:
            req.sendall("Nope\n")
        req.close()


class ThreadedServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass

if __name__ == "__main__":
    HOST, PORT = '0.0.0.0', 10001
    print HOST
    print PORT
    server = ThreadedServer((HOST, PORT), Task)
    server.allow_reuse_address = True
    server.serve_forever()
