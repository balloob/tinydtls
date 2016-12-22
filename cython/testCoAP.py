import DTLSSocket, dtls
s = DTLSSocket.DTLSSocket()
s.bind(("::", 5683, 0, 0))

group = "ff12::42"
port  = "5683"
psk = "demosecret"
gid = "0"
print(group, port, psk, gid)
s.joinMC(group=group, port=int(port), role=dtls.DTLS_SERVER, psk=psk.encode("utf-8"), gid=int(gid))
while True:
  print(s.recvmsg(1200, cnt=50))
