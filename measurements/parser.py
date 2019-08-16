import subprocess
import os

l = list()

p = subprocess.Popen(('sudo', 'sh', 'tcpread.sh'), stdout=subprocess.PIPE)
for row in iter(p.stdout.readline, b''):
    l.append(float(row.rstrip().decode().split(':')[2]))

m = [j-i for i, j in zip(l[:-1], l[1:])]

def avg(lst):
    return sum(lst) / len(lst)

print(str(1000*avg(m)) + " ms")
