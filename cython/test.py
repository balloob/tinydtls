import dtls, time

def read(x, y):
  print("> read:", x, y)
  return len(y)

def write(x, y):
  print("< write:", x, y)
  return len(y)

def pprint(x):
  print("\n---", x, "---")

#dtls.setLogLevel(dtls.DTLS_LOG_DEBUG)
print("Log Level:", dtls.dtlsGetLogLevel())

print("\nClient connect")

d = dtls.DTLS(read=read, write=write)
pprint("connect:")
s = d.connect("::1", 20220)
assert s == d.getSessionFromAddress("::1")

pprint("try to send data")
assert d.write(s, b"Test!") == 0 #peer not yet connected

pprint("close connection")
d.close(s)
d.resetPeer(s)
