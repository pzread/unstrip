import sys
import json
import functools
import multiprocessing

from ir import *

def blkcost(a = None,b = None):
    assert(a != None or b != None)

    if a == None or b == None:
        if a == None:
            x = b
        if b == None:
            x = a
        cost = 0
        for ins in x:
            cost += inscost(ins,None)
        return cost

    return distance(a,b,inscost,max(len(a),len(b)) * 8)

def inscost(a = None,b = None):
    if a == None or b == None:
        return 4
    if a[0] != b[0]:
        return 4
    opa = a[1]
    opb = b[1]
    if len(opa) != len(opb):
        return 4
    cost = 0
    for x,y in zip(opa,opb):
        if x[0] != y[0]:
            cost = max(cost,2)
        for pa,pb in zip(x[1:],y[1:]):
            if pa != pb:
                cost = max(cost,1)
                break
    return cost

def distance(obja,objb,costfunc,limit):
    dp = list()
    for i in range(len(obja) + 1):
        col = list()
        for j in range(len(objb) + 1):
            col.append(-1)
        dp.append(col)
    
    dp[0][0] = 0
    for i in range(1,len(obja) + 1):
        dp[i][0] = dp[i - 1][0] + costfunc(obja[i - 1],None)
    for i in range(1,len(objb) + 1):
        dp[0][i] = dp[0][i - 1] + costfunc(None,objb[i - 1])

    for i in range(1,len(obja) + 1):
        for j in range(1,len(objb) + 1):
            if min(dp[i - 1][j - 1],dp[i - 1][j],dp[i][j - 1]) > limit:
                dp[i][j] = 10 ** 9
            else:
                dp[i][j] = min(
                        dp[i - 1][j - 1] + costfunc(obja[i - 1],objb[j - 1]),
                        dp[i - 1][j] + costfunc(obja[i - 1],None),
                        dp[i][j - 1] + costfunc(None,objb[j - 1]))
    return dp[-1][-1]

libfins = json.loads(open(sys.argv[1],'r').read())
elffins = json.loads(open(sys.argv[2],'r').read())

def find(x):
    fina = x[0][1]
    finb = x[1][1][1]

    '''
    limit = max(
            sum(map(lambda blk: len(blk),fina)),
        sum(map(lambda blk: len(blk),finb))
    )
    '''
    limit = 1024

    return (distance(fina,finb,blkcost,limit * 6),x[1][0])

tfidf = TFIDF()
for name,fin in libfins.items():
    tfidf.addDocument(name,bigram(fin[1]))

pool = multiprocessing.Pool(1)
for na,fina in elffins.items():
    scores = tfidf.similarities(bigram(fina[1]))
    scores.sort(key = lambda x: x[1])
    names = list(map(lambda x: x[0],scores[-64:]))

    narrow = list(filter(lambda x: x[0] in names,libfins.items()))

    res = pool.map(find,map(lambda x: (fina,x),narrow))
    res.sort(key = lambda x: x[0])
    
    if res[0][0] == res[1][0]:
        continue

    dis,name, = res[0]
    f = 1.0
    for x in scores:
        if x[0] == name:
            f = x[1]

    print('%s %s %s %f %d'%(na,name,dis,f,fina[0]))
    sys.stdout.flush()
