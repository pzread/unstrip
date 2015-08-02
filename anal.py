import json
import collections

def trigram(liss):
    gram = collections.defaultdict(int)
    for lis in liss:
        if len(lis) < 3:
            lis += [-1] * (len(lis) - 3)

        for i in range(len(lis) - 2):
            s = '%d-%d-%d'%(lis[i][0],lis[i + 1][0],lis[i + 2][0])
            gram[s] += 1
    return gram

'''
data = collections.defaultdict(list)
for i in range(1,7 + 1):
    funcfin = json.load(open('dump-%d'%i,'r'))
    for func in funcfin.values():
        name = func[0]
        data[name].append(func)

findic = dict()
for name,finlist in data.items():
    if len(finlist) < 7:
        continue
    findic[name] = finlist

filed = collections.defaultdict(list)
label = 0
for name,funcs in findic.items():
    label += 1
    for idx,func in enumerate(funcs):
        gram = trigram(list(func[1].values()))
        filed[idx].append((label,gram))
        
for idx in range(0,7):
    open('gram-%d'%(idx + 1),'w').write(json.dumps(filed[idx]))
'''

data = collections.defaultdict(list)
funcfin = json.load(open('dump-a','r'))
for func in funcfin.values():
    name = func[0]
    data[name].append(func)

findic = dict()
for name,finlist in data.items():
    if len(finlist) < 1:
        continue
    findic[name] = finlist

filed = collections.defaultdict(list)
label = 0
for name,funcs in findic.items():
    label += 1
    for idx,func in enumerate(funcs):
        gram = trigram(list(func[1].values()))
        filed[idx].append((label,gram))
        
open('gram-a','w').write(json.dumps(filed[0]))

