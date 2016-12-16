import dtls, time, socket

sock = socket.socket(family=socket.AF_INET6, type=socket.SOCK_DGRAM)
sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVPKTINFO, 1)
sock.bind(('', 20220, 0, 0))

def read(x, y):
  print("> read:", x, y)
  return len(y)

def write(x, y):
  #print("< write:", x, y.hex())
  ip, port = x
  return sock.sendto(y, x)

lastEvent = 0
def event(level, code):
  global lastEvent
  lastEvent = code

def pprint(x):
  print("\n---", x, "---")

def querySock(sock, d):
  data, ancdata, flags, src = sock.recvmsg(1200, 100)
  #print("Got:", data, ancdata, flags, src)
  dst = 0
  mc = False
  for cmsg_level, cmsg_type, cmsg_data in ancdata:
        if (cmsg_level == socket.IPPROTO_IPV6 and cmsg_type == socket.IPV6_PKTINFO):
          if cmsg_data[0] == 0xFF:
            dst = socket.inet_ntop(socket.AF_INET6, cmsg_data[:16])
            mc = True
  if mc:
    d.handleMessageAddr(dst, 0, data, mc)
  else:
    d.handleMessageAddr(src[0], src[1], data, mc)


#dtls.setLogLevel(dtls.DTLS_LOG_DEBUG)
print("Log Level:", dtls.dtlsGetLogLevel())

d = dtls.DTLS(read=read, write=write, event=event, pskId=b"Client_identity", pskStore={b"Client_identity": b"secretPSK"})

while True:
  querySock(sock, d)
