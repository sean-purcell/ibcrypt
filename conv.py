n = int(raw_input())
lines = []
for i in range(0, n):
    line = raw_input()
    split = line.split(' ')
    nline = '"' + split[0] + '", "' + split[1] + '",'
    lines.append(nline)
    
for i in range(0, n):
    print lines[i]