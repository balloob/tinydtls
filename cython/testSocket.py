import dtls, time, socket

s = socket.socket(family=socket.AF_INET6, type=socket.SOCK_DGRAM)
s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVPKTINFO, 1)

def read(x, y):
  print("> read:", x, y.hex())
  return len(y)

def write(x, y):
  print("< write:", x, y.hex())
  ip, port = x
  return s.sendto(y, x)

def pprint(x):
  print("\n---", x, "---")

#dtls.setLogLevel(dtls.DTLS_LOG_DEBUG)
print("Log Level:", dtls.dtlsGetLogLevel())

print("\nClient connect")

d = dtls.DTLS(read=read, write=write, pskId=b"Client_identity", pskStore={b"Client_identity": b"secretPSK"})

pprint("connect:")
d.connect("::1", 20220)

#now = time.
while True:
  data, ancdata, flags, src = s.recvmsg(1200, 100)
  dst = 0
  mc = False
  for cmsg_level, cmsg_type, cmsg_data in ancdata:
        if (cmsg_level == socket.IPPROTO_IPV6 and cmsg_type == socket.IPV6_PKTINFO):
          if cmsg_data[0] == 0xFF:
            dst = socket.inet_ntop(socket.AF_INET6, cmsg_data[:16])
            mc = True
  if mc:
    print(d.handleMessageAddr(dst, 0, data, mc))
  else:
    print(d.handleMessageAddr(src[0], src[1], data, mc))

pprint("try to send data")
print("try write:", d.write(s, b"Test!"))

pprint("close connection")
d.close(s)
d.resetPeer(s)
