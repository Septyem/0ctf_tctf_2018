import os
from pwn import *

context.log_level='debug'

#c = remote('127.0.0.1', 10001)
c = remote('192.168.201.11', 10001)
prefix = c.recvline().decode('base64')
f = open('prefix','wb')
f.write(prefix)
f.close()
os.system('./a.out')
f = open('coll0','rb')
a0 = f.read()
f.close()
f = open('coll1','rb')
a1 = f.read()
f.close()
print prefix.encode('hex')
print a0.encode('hex')
print a1.encode('hex')
ans = a0.encode('base64').strip()+':'+a1.encode('base64').strip()
ans = ans.replace('\n','')
c.sendline(ans)
print c.recvline()
c.interactive()
