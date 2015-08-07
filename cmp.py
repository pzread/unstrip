sf = open('output_ir','r')

a = list()
c = 0
ma = 0
for l in sf:
    part = l[:-1].split(' ')
    if part[0] in part[1] or part[1] in part[0]:
        if(int(part[2]) > 1024):
            continue
        c += 1
        ma = max(ma,float(part[2]))
print(ma)
print(c)
