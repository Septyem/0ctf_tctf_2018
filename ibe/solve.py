from libnum import jacobi
from Crypto.Util.number import *
import string
import random
from hashlib import sha256
from pwn import *

#context.log_level='debug'

def dopow():
    chal = c.recvline()
    post = chal[12:28]
    tar = chal[33:-1]
    c.recvuntil(':')
    found = iters.bruteforce(lambda x:sha256(x+post).hexdigest()==tar, string.ascii_letters+string.digits, 4)
    c.sendline(found)

def crm(n, a):
    sum = 0
    prod = reduce(lambda a, b: a*b, n)
    for n_i, a_i in zip(n, a):
        p = prod / n_i
        sum += a_i * mul_inv(p, n_i) * p
    return sum % prod


def mul_inv(a, b):
    b0 = b
    x0, x1 = 0, 1
    if b == 1: return 1
    while a > 1:
        q = a / b
        a, b = b, a%b
        x0, x1 = x1 - q * x0, x0
    if x1 < 0: x1 += b0
    return x1



def getmsg():
    c.recvuntil('> ')
    c.sendline('1')
    out = []
    for i in range(128):
        res = c.recvline()
        c1, c2 = map(int, res.split(' '))
        out.append((c1,c2))
    return out

def resetfast():
    c.recvuntil('> ')
    c.sendline('3')
    c.recvuntil('[Y/n] ')
    c.sendline('Y')

def getoracle(i):
    c.recvuntil('> ')
    c.sendline('4')
    c.recvuntil('number: ')
    c.sendline(str(i))
    res = c.recvline()
    return int(res.split(' ')[0])

def guess(sec):
    c.recvuntil('> ')
    c.sendline('5')
    c.recvuntil('(hex): ')
    c.sendline(sec.encode('hex'))
    print c.recvline()


def getrec(i):
    rr = pow(r, (i-1)/2)
    oo = getoracle(i)
    if oo==0:
        return 0
    else:
        return rr/oo
        
'''
for i in range(100):
    x=getRandomRange(0,p-1)
    if x%2==0:
        continue
    if getrec(x)!=jacobi(p,x):
        print getrec(x)
        print jacobi(p,x)
        print jacobi(x,p)
    assert getrec(x)==jacobi(p,x)
print 'ok'
exit()
'''

pp=[]
for i in range(10000):
    if isPrime(i):
        pp.append(i)

for i in range(400):
    if i==0:
        jtable=[[]]
        continue
    ii=pp[i]
    tmp=[0]
    for j in range(1,ii):
        tmp.append(jacobi(j,ii))
    jtable.append(tmp)

pused = [2]
dused = [{}]
delta=24
for i in range(400):
    if i==0:
        prod=2
        continue
    ii=pp[i]
    dic={}
    ok=True
    for j in range(1,ii):
        #tmp=(j-delta)%ii
        tmp=j
        hh=0
        for k in range(delta):
            hh=hh*3+jtable[i][tmp]+1
            tmp=(tmp+4)%ii
        if dic.get(hh)!=None:
            ok=False
            break
        dic[hh]=j
    if ok:
        pused.append(ii)
        dused.append(dic)
        prod*=ii
    if prod>(1<<2048):
        print 'ok',delta,'in',i
        break

print len(pused)
#c = remote('127.0.0.1', 10002)
c = remote('192.168.201.11', 10002)
dopow()

c.recvuntil('n:')
n = int(c.recvline())

out = getmsg()
r = getoracle(-1)

oracles = []
for j in range(delta):
    tmp = []
    for i in range(1,len(pused)):
        tmp.append(getrec(pused[i]))
    oracles.append(tmp)
    resetfast()

mods = [1]
for i in range(1,len(pused)):
    ii = pused[i]
    hh=0
    #for j in range(-delta, delta, 2):
    for j in range(delta):
        hh = hh*3 + oracles[j][i-1] + 1
    if dused[i].get(hh)==None:
        print ii,p%ii
        print hh
        print dused[i]
    m = dused[i][hh]
    mods.append(m)

p = crm(pused, mods)

assert n%p==0
q = n/p

def getkey(id, n, p, q):
    seed = sha256(id).digest()
    cand = ''
    for i in range(16):
        cand += seed
        seed = sha256(seed).digest()
    cand = int(cand.encode('hex'), 16) % n
    while jacobi(cand,n) != 1:
        cand = (cand+1) % n
    priv = pow(cand, (n+5-p-q)/8, n)
    return cand, priv

def decrypt(c1, c2, a, r, n):
    if pow(r,2,n)==a:
        x = (c1 + 2*r) % n
    else:
        x = (c2 + 2*r) % n
    return jacobi(x, n)

a,r = getkey('Alice', n, p, q)
sec = ''
for i in range(128):
    m = decrypt(out[i][0], out[i][1], a, r, n)
    if m==1:
        sec += '1'
    else:
        sec += '0'
sec = int(sec,2)
sec = long_to_bytes(sec)
guess(sec)


'''
f = open('flag.enc')
n = f.readline()
n = int(n)
out = f.readline()
f.close()
out = eval(out)
print len(out)
'''
