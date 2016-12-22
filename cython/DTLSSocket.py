import socket, dtls

DTLS_CLIENT = dtls.DTLS_CLIENT
DTLS_SERVER = dtls.DTLS_SERVER

class DTLSSocket():
  app_data = None
  connected = dict()
  lastEvent = None
  inbuffer = None
  outancbuff = None
  _sock = None
  
  def __init__(self, pskId=b"Client_identity", pskStore={b"Client_identity": b"secretPSK"}):
    self._sock = socket.socket(family=socket.AF_INET6, type=socket.SOCK_DGRAM)
    self._sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVPKTINFO, 1)
    self.d = dtls.DTLS(read=self._read, write=self._write, event=self._event, pskId=pskId, pskStore=pskStore)
    print("Init done:", self._sock, self.d)
  
  def __del__(self):
    print("Destroying", self)
    self.connected.clear()
    self.d = None
    self._sock = None
  
  def _read(self, x, y):
    if self.app_data:
      print("_read: lost", x, y)
    self.app_data = (y, x)
    return len(y)

  def _write(self, x, y):
    if self.outancbuff:
      ret = self._sock.sendmsg([y,], self.outancbuff[0], self.outancbuff[1], x)
      self.outancbuff = None
      return ret
    else:
      return self._sock.sendto(y, x)
  
  def _event(self, level, code):
    self.lastEvent = code
  
  def sendmsg(self, data, ancdata=[], flags=0, address=None, cnt=10):
    data = b''.join(data)
    
    if address not in self.connected:
      print("connecting...", address)
      addr, port, flowinfo, scope_id = address
      self.lastEvent = None
      s = self.d.connect(addr, port, flowinfo, scope_id)
      if not s:
        raise Exception
      while self.lastEvent != 0x1de and cnt>0:
        try:
          indata = self.recvmsg(1200, cnt=1)
        except (BlockingIOError, InterruptedError):
          pass
        else:
          self.inbuffer = indata
        cnt -= 1
      
      if self.lastEvent == 0x1de:
        self.connected[address] = s
      else:
        raise BlockingIOError
    
    if self.outancbuff:
      print("ERROR: self.outancbuff is not None!")
    self.outancbuff = (ancdata, flags)
    return self.d.write(self.connected[address], data)
    
  def recvmsg(self, buffsize, ancbufsize=100, flags=0, cnt=3):
    data = None
    ancdata = None
    src = None
    while not self.app_data and cnt > 0:
      if self.inbuffer:
        data, ancdata, flags, src = self.inbuffer
      else:
        data, ancdata, flags, src = self._sock.recvmsg(buffsize, ancbufsize, flags)
      
      dst = 0
      mc = False
      for cmsg_level, cmsg_type, cmsg_data in ancdata:
            if (cmsg_level == socket.IPPROTO_IPV6 and cmsg_type == socket.IPV6_PKTINFO):
              if cmsg_data[0] == 0xFF:
                dst = (socket.inet_ntop(socket.AF_INET6, cmsg_data[:16]), self._sock.getsockname()[1])
                print("Debug: dst =", dst)
                mc = True
      if mc:
        ret = self.d.handleMessageAddr(dst[0], dst[1], data, mc)
        if ret != 0:
          raise Exception("handleMessageAddr returned", ret)
      else:
        if self.d.handleMessageAddr(src[0], src[1], data, mc) != 0:
          raise Exception("handleMessageAddr returned", ret)
      
      cnt -= 1
    if self.app_data:
      data, addr = self.app_data
      self.app_data = None
      return data, ancdata, flags, addr
    else:
      raise BlockingIOError
  
  def __getattr__(self, attr):
    print(attr)
    return getattr(self._sock, attr)
  
  def joinMC(self, group, port, role, psk, gid=0, flowinfo=0, scope_id=0, join=True):
    if join:
      if role == dtls.DTLS_SERVER:
        self.d.joinLeaveGroupe(group, self, join=True)
        s = self.d.fakeKeyBlock(group, port, role, psk, gid)
      else:
        s = self.d.fakeKeyBlock(group, port, role, psk, gid)
      self.connected[(group, port, flowinfo, scope_id)] = s
    else:
      self.connected.pop((group, port, flowinfo, scope_id))
