import dtls, socket

ret = b""

def read(x, y):
#  print("> read:", x, y)
  global ret
  ret = y
  return len(y)

def write(x, y):
#  print("< write:", x, y)
  global ret
  ret = y
  return len(y)

def pprint(x):
  print("\n---", x, "---")

def pprintC(x):
  print(" "+"*"*(len(x)+4))
  print(" *", x, "*")
  print(" "+"*"*(len(x)+4))

pprintC("Server MC")

srv = dtls.DTLS(read=read, write=write)

pprint("joinMC")
sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
srv.joinLeaveGroupe("FF12::42", sock, True)

pprint("Fake Keys")
s = srv.fakeKeyBlock("FF12::42", dtls.DTLS_SERVER, b"secret", 0)

pprint("send data to group")
assert srv.write(s, b"Test!") == 5
assert ret == b'\x17\xfe\xfd\x00\x01\x00\x00\x00\x00\x00\x00\x00\x15\x00\x01\x00\x00\x00\x00\x00\x00\xb4\xc5\xaf\xff\x17\xce\xee\xae\xac:\xa2X\x94'

pprint("handle Message from client")
msg = b"\x17\xfe\xfd\x00\x01\x17\x00\x00\x00\x00\x00\x00\x15\x00\x01\x17\x00\x00\x00\x00\x00\xf5A\x1b\x96%\xdb\xfd\xd4\x12'\x06\xbdQ"
assert srv.handleMessageAddr("FF12::42", 0, msg, 1) == 0
assert ret == b"Test!"

pprint("check pending")
assert srv.checkRetransmit() == 0

srv.joinLeaveGroupe("FF12::42", sock, False)
