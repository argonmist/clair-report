fo = open('/home/argon/Downloads/critical-raw.txt', 'r')
item = fo.readlines()
s = "" 
for index in range(len(item)):
  s = "  "+ item[index].strip()+": zlib\n"
  fo2 = open('/home/argon/Downloads/critical.yaml','a')
  fo2.write(s)
fo2.close()
