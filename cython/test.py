import dtls, time

def read(x, y):
  print("> read:", x, y)
  return len(y)

def write(x, y):
  print("< write:", x, y)
  ip, port = x
  return len(y)

def pprint(x):
  print("\n---", x, "---")

#dtls.setLogLevel(dtls.DTLS_LOG_DEBUG)
print("Log Level:", dtls.dtlsGetLogLevel())

print("\nClient connect")

d = dtls.DTLS(read=read)
e = dtls.DTLS(read=read)

def writed(x, y):
  addr, port = x
  print('< write d', addr, port, y)
  return len(y) if d.handleMessageAddr(addr, port, y, 0) == 0 else 0

def writee(x, y):
  addr, port = x
  print('< write e', addr, port, y)
  return len(y) if e.handleMessageAddr(addr, port, y, 0) == 0 else 0

d.pycb['write'] = writee #lambda x,y: y if e.handleMessage(dtls.Session(x[0], x[1]), y, 0) == 0 else 0
e.pycb['write'] = writed

print(d.pycb)
print(e.pycb)


pprint("connect:")
s = d.connect("::1", 20220)

pprint("try to send data")
print(d.write(s, b"Test!")) # == 0 #peer not yet connected

pprint("close connection")
d.close(s)
d.resetPeer(s)
