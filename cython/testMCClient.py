import dtls

ret = b""

def read(x, y):
  #print("> read:", x, y)
  global ret
  ret = y
  return len(y)

def write(x, y):
  #print("< write:", x, y)
  global ret
  ret = y
  return len(y)

def pprint(x):
  print("\n---", x, "---")

def pprintC(x):
  print(" "+"*"*(len(x)+4))
  print(" *", x, "*")
  print(" "+"*"*(len(x)+4))

pprintC("Client MC")

c = dtls.DTLS(read=read, write=write)

pprint("Fake Keys")
s = c.fakeKeyBlock("FF12::42", dtls.DTLS_CLIENT, b"secret", 23)

pprint("send data to group")
assert c.write(s, b"Test!") == 5
assert ret == b"\x17\xfe\xfd\x00\x01\x17\x00\x00\x00\x00\x00\x00\x15\x00\x01\x17\x00\x00\x00\x00\x00\xf5A\x1b\x96%\xdb\xfd\xd4\x12'\x06\xbdQ"

pprint("handle Message from server")
msg = b'\x17\xfe\xfd\x00\x01\x00\x00\x00\x00\x00\x00\x00\x15\x00\x01\x00\x00\x00\x00\x00\x00\xb4\xc5\xaf\xff\x17\xce\xee\xae\xac:\xa2X\x94'
assert c.handleMessageAddr("FF12::42", 0, msg, 1) == 0
assert ret == b"Test!"

pprint("handle Message without peer")
msg = b"\x17\xfe\xfd\x00\x01\x17\x00\x00\x00\x00\x00\x00\x15\x00\x01\x17\x00\x00\x00\x00\x00\xf5A\x1b\x96%\xdb\xfd\xd4\x12'\x06\xbdQ"
assert c.handleMessageAddr("::42", 0, msg, 1) == -1

pprint("check pending")
print("come again at:", c.checkRetransmit())
assert c.checkRetransmit() == 0
