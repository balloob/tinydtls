import dtls

#dtls.setLogLevel(dtls.DTLS_LOG_DEBUG)

msgC = []
msgS = []

def writeS(x, y):
  print("< writeS:", x, y)
  global msgC
  msgC.append((x, y))
  return len(y)

def writeC(x, y):
  print("< writeC:", x, y)
  global msgS
  msgS.append((x, y))
  return len(y)

def read(x, y):
  print("> read:", x, y)
  return len(y)

def pprint(x):
  print("\n---", x, "---")

def pprintC(x):
  print(" "+"*"*(len(x)+4))
  print(" *", x, "*")
  print(" "+"*"*(len(x)+4))

clt = dtls.DTLS(read=read, write=writeC)

sc = clt.fakeKeyBlock("FF12::42", dtls.DTLS_CLIENT, b"secret", 23)

clt.write(sc, b"Test!")

srv = dtls.DTLS(read=read, write=writeS)

ss = srv.fakeKeyBlock("FF12::42", dtls.DTLS_SERVER, b"secret", 0)

(ip, port), msg = msgS.pop()
print("Handle:     {ip},  {port}, {msg}".format(ip=ip, port=port, msg=msg))
srv.handleMessageAddr(ip, port, msg[:], True)
