import DTLSSocket
s = DTLSSocket.DTLSSocket()
s.bind(("::", 2342, 0, 0))
s.joinMC("ff12::42", 2342, DTLSSocket.DTLS_SERVER, b"secret")
print(s.recvmsg(1200, cnt=50))
print(s.recvmsg(1200, cnt=50))
