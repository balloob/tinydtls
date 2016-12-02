cimport tdtls
from tdtls cimport dtls_context_t, dtls_handler_t, session_t, dtls_alert_level_t, dtls_credentials_type_t
from libc.stdint cimport uint8_t
from libc.stddef cimport size_t
ctypedef uint8_t uint8
import socket

DTLS_CLIENT = tdtls.DTLS_CLIENT
DTLS_SERVER = tdtls.DTLS_SERVER


cdef int _write(dtls_context_t *ctx, session_t *session, uint8 *buf, size_t len):
  """Send data to socket"""
  self = <object>(ctx.app)
  data = buf[:len]
  assert session.addr.sin6.sin6_family == socket.AF_INET6
  ip   = socket.inet_ntop(socket.AF_INET6, session.addr.sin6.sin6_addr.s6_addr[:16])
  port = session.addr.sin6.sin6_port
  return self.pycb['write']((ip, port), data)
  
cdef int _read(dtls_context_t *ctx, session_t *session, uint8 *buf, size_t len):
  """Send data to application"""
  self = <object>(ctx.app)
  data = buf[:len]
  assert session.addr.sin6.sin6_family == socket.AF_INET6
  ip   = socket.inet_ntop(socket.AF_INET6, session.addr.sin6.sin6_addr.s6_addr[:16])
  port = session.addr.sin6.sin6_port
  return self.pycb['read']((ip, port), data)
  
cdef int _event(dtls_context_t *ctx, session_t *session, dtls_alert_level_t level, unsigned short code):
  """The event handler is called when a message from the alert protocol is received or the state of the DTLS session changes."""
  print("event:", level, code)
  return 0;

cdef int _get_psk_info(dtls_context_t *ctx,
		      const session_t *session,
		      dtls_credentials_type_t req_type,
		      const unsigned char *desc_data,
		      size_t desc_len,
		      unsigned char *result_data,
		      size_t result_length):
  """Called during handshake to get information related to the psk key exchange. 
   
   The type of information requested is indicated by @p type 
   which will be one of DTLS_PSK_HINT, DTLS_PSK_IDENTITY, or DTLS_PSK_KEY.
   
   The called function must store the requested item in the buffer @p result 
   of size @p result_length. 
   On success, the function must return
   the actual number of bytes written to @p result, or a
   value less than zero on error. The parameter @p desc may
   contain additional request information (e.g. the psk_identity
   for which a key is requested when @p type == @c DTLS_PSK_KEY.
   
   @param ctx     The current dtls context.
   @param session The session where the key will be used.
   @param type    The type of the requested information.
   @param desc    Additional request information
   @param desc_len The actual length of desc.
   @param result  Must be filled with the requested information.
   @param result_length  Maximum size of @p result.
   @return The number of bytes written to @p result or a value
           less than zero on error. """
  self = <object>(ctx.app)
  
  assert session.addr.sin6.sin6_family == socket.AF_INET6
  ip   = ':'.join(hex(session.addr.sin6.sin6_addr.__u6_addr.__u6_addr8))
  port = session.addr.sin6.sin6_port
  
  desc = desc_data[:desc_len]
  result  = result_data[:result_length]
  
  print("psk: TODO...")
  
  return 0

cdef class Session:
    cdef session_t session
    def __cinit__(self, addr, int port=0, int flowinfo=0, int scope_id=0):
      assert sizeof(self.session.addr.sin6) == 28
      self.session.size = sizeof(self.session.addr.sin6)
      self.session.addr.sin6.sin6_family   = socket.AF_INET6
      self.session.addr.sin6.sin6_addr.s6_addr = socket.inet_pton(socket.AF_INET6, addr)
      self.session.addr.sin6.sin6_port     = port
      self.session.addr.sin6.sin6_flowinfo = flowinfo
      self.session.addr.sin6.sin6_scope_id = scope_id
      self.session.ifindex = 0
    property family:
      def __get__(self):
        return self.session.addr.sin6.sin6_family
    property addr:
      def __get__(self):
        return self.session.addr.sin6.sin6_addr.s6_addr
    property port:
      def __get__(self):
        return self.session.addr.sin6.sin6_port
    property flowinfo:
      def __get__(self):
        return self.session.addr.sin6.sin6_flowinfo
    property scope_id:
      def __get__(self):
        return self.session.addr.sin6.sin6_scope_id
    property ifindex:
      def __get__(self):
        return self.session.ifindex
    cdef session_t* getSession(self):
        return &self.session
    cdef p(self):
      #print(self.session)
      pass

cdef class DTLS:
  cdef dtls_context_t *ctx
  cdef dtls_handler_t cb
  cdef object _sock
  pycb = dict()
  sessions = []
  
  def __cinit__(self):
    tdtls.dtls_init()
    self.ctx = tdtls.dtls_new_context(<void*>self)
    
  def __dealloc__(self):
    tdtls.dtls_free_context(self.ctx)
    self.cb.write = _write
    self.cb.read  = _read
    self.cb.event = _event
    self.cb.get_psk_info = _get_psk_info
    tdtls.dtls_set_handler(self.ctx, &self.cb)
    
  def __init__(self, sock=None, read=None, write=None):
    if sock == None:
      sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    self._sock  = sock
    if read == None:
      read = self.p
    self.pycb['read']  = read
    if write == None:
      write = self.p
    self.pycb['write'] = write
  
  def p(x, y):
    print("default cb, addr:", x,"data:", y)
  
  #int dtls_connect(dtls_context_t *ctx, const session_t *dst)
  def connect(self, addr, port=0, flowinfo=0, scope_id=0):
    session = Session(addr, port=0, flowinfo=0, scope_id=0)
    session.p()
    if tdtls.dtls_connect(self.ctx, session.getSession()):
      self.sessions.append(session)
  
  #int dtls_close(dtls_context_t *ctx, const session_t *remote)
  
  #int dtls_write(dtls_context_t *ctx, session_t *session, uint8 *buf, size_t len)
  
  #void dtls_check_retransmit(dtls_context_t *context, clock_time_t *next)
  
  #int dtls_handle_message(dtls_context_t *ctx, session_t *session, uint8 *msg, int msglen, uint8 is_multicast)
  
  #int joinmc(char *group, sockaddr_in6 *dst, int fd)
  def joinLeaveGroupe(self, group, join=True):
    """join/leave multicast group"""
    import struct
    
    addrinfo = socket.getaddrinfo(group, None, type=socket.SOCK_DGRAM)[0]
    ga = b""
    try:
      ga = socket.inet_pton(addrinfo[0], addrinfo[4][0])
      assert addrinfo[0] == socket.AF_INET6
      mreq = ga + struct.pack('@I', 0)
      if join:
        self._sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
      else:
        self._sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_LEAVE_GROUP, mreq)
    except OSError as e:
      print(e)
      return False
    return True
  
  #int fake_key_block(session_t *dst, dtls_context_t *ctx, dtls_peer_type role, unsigned char *psk, uint8_t groupid)
  def fake_key_block(self, group, tdtls.dtls_peer_type role, unsigned char* psk, uint8_t gid):
    cdef session_t session
    session.addr.sin6.sin6_family   = socket.AF_INET6
    session.addr.sin6.sin6_addr.s6_addr = socket.inet_pton(socket.AF_INET6, group)
    session.addr.sin6.sin6_port     = 0
    session.addr.sin6.sin6_flowinfo = 0
    session.addr.sin6.sin6_scope_id = 0
    #print("session.addr.sin6", session.addr.sin6, type(session.addr.sin6))
    #print(session.addr.sin6.sin6_addr.s6_addr[:16])
    if(tdtls.fake_key_block(&session, self.ctx, role, psk, gid) < 0):
      raise
