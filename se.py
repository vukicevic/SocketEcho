import select
import socket
import hashlib
import base64
import struct
import time
from BaseHTTPServer import BaseHTTPRequestHandler
from StringIO import StringIO

class HTTPRequest(BaseHTTPRequestHandler):
  def __init__(self, request_text):
    self.rfile = StringIO(request_text)
    self.raw_requestline = self.rfile.readline()
    self.error_code = self.error_message = None
    self.parse_request()

  def send_error(self, code, message):
    self.error_code = code
    self.error_message = message

class WSFrame():
  def __init__(self, data=None):
    self.final    = 0
    self.opcode   = 0
    self.masked   = False
    self.length   = 0
    self.mask     = []
    self.payload  = []
    self.time     = time.time()
    self.complete = False
    
    if data:
      self.final    = 1
      self.opcode   = 1
      self.extendPayload(data)
      self.complete = True

  def setExtendedLength(self, v):
    if (self.length < 126):
      return

    if (self.length == 126):
      self.length = struct.unpack(">H", ''.join([chr(x) for x in v]))[0]
    else:
      self.length = struct.unpack(">Q", ''.join([chr(x) for x in v]))[0]

  def applyMask(self, data, msk):
    out = list(data)
    for j in range(0, len(data)):
      out[j] = data[j] ^ msk[j%4]

    return out

  def toString(self, mskd=False):
    out = [self.final << 7 | self.opcode, ]
    if self.length < 126:
      out.append(self.length)
    elif self.length < 65536:
      out.append(126)
      out.append(self.length >> 8)
      out.append(self.length & 255)
    else:
      out.append(127)
      out.append(self.length >> 56)
      out.append(self.length >> 48 & 255)
      out.append(self.length >> 40 & 255)
      out.append(self.length >> 32 & 255)
      out.append(self.length >> 24 & 255)
      out.append(self.length >> 16 & 255)
      out.append(self.length >> 8 & 255)
      out.append(self.length & 255)

    if mskd and len(self.mask) == 4:
      out[1] |= 128
      out.extend(self.mask)
      if self.masked:
        out.extend(self.payload)
      else:
        out.extend(self.applyMask(self.payload, self.mask))
    else:
      if self.masked: #if masked, mskd is false so unmask
        out.extend(self.applyMask(self.payload, self.mask))
      else:
        out.extend(self.payload)

    return ''.join([chr(x) for x in out])

  def extendPayload(self, data, prepend=False):
    self.length += len(data)
    temp = self.applyMask(struct.unpack('%sB' % len(data), data), self.mask) if self.masked else list(struct.unpack('%sB' % len(data), data))

    if prepend:
      temp.extend(self.payload)
      self.payload = temp
    else:
      self.payload.extend(temp)

class WSClient():
  def __init__(self, address):
    self.ip  	  = address[0]
    self.port   = address[1]
    self.path   = ''
    self.ready  = False
    self.ping   = 0
    self.pong   = 0

    self.rb  = []
    self.fb  = []
    self.ptr = 0

  def parse(self):
    if self.ptr == 0:
      self.parseHeader()

    self.parseBody()
  
  def parseHeader(self):
    if len(self.rb) < 2 or self.ptr > 0:
      return

    self.fb.append(WSFrame())

    self.fb[-1].final = (self.rb[0] & 128) >> 7
    self.fb[-1].opcode = self.rb[0] & 15
    if self.rb[1] & 128 > 0:
      self.fb[-1].masked = True
    self.fb[-1].length = self.rb[1] & 127

    self.ptr = 2

  def parseBody(self):
    if self.ptr == 2:
      if self.fb[-1].length == 126:
        if len(self.rb) < 4:
          return False
        self.fb[-1].setExtendedLength(self.rb[2:4])
        self.ptr = 4
      elif self.fb[-1].length == 127:
        if len(self.rb) < 10:
          return False
        self.fb[-1].setExtendedLength(self.rb[2:10])
        self.ptr = 10

    if self.fb[-1].masked and len(self.fb[-1].mask) == 0:
      if len(self.rb) < (self.ptr+4):
        return False
      self.fb[-1].mask = self.rb[self.ptr:self.ptr+4]
      self.ptr += 4

    if len(self.rb) < self.ptr+self.fb[-1].length:
      return False

    self.fb[-1].payload  = self.rb[self.ptr:self.ptr+self.fb[-1].length]
    self.fb[-1].complete = True
    self.rb              = self.rb[self.ptr+self.fb[-1].length:]
    self.ptr             = 0
    
    print 'Frame type %d received length %d at %f' % (self.fb[-1].opcode, self.fb[-1].length, self.fb[-1].time)
    
    if (len(self.rb) > 0):
      self.parse()

  def recvData(self, data):
    self.rb.extend(list(struct.unpack('%sB' % len(data), data)))
    self.parse()

  def recvHandshake(self, data):
    try:
      request = HTTPRequest(data)
      if request.error_code != None or request.command != 'GET' or request.headers['sec-websocket-version'] != '13' or request.headers['upgrade'] != 'websocket':
        return "HTTP/1.1 400 Bad Request\r\n\r\n"
      if request.headers['origin'] != '':
        pass
      key = request.headers['sec-websocket-key']
    except e:
      return "HTTP/1.1 400 Bad Request\r\n\r\n"

    self.path = request.path
    self.ready = True

    hash = base64.b64encode(hashlib.sha1('%s%s' % (key, '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')).digest())
    return "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n" % (hash)

  def popFrameBuffer(self):
    if len(self.fb) > 0 and self.fb[0].complete:
      return self.fb.pop(0)
    else:
      return None

class WSServer():
  def __init__(self, port=3490):
    self.handler = [self.hX, self.h1, self.hX, self.hX, self.hX, self.hX, self.hX, self.hX, self.h8, self.h9, self.hA, self.hX, self.hX, self.hX, self.hX, self.hX]
    self.servers = {}
    
    self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    self.server.bind(('',port))
    self.server.listen(5)

    self.servers[self.server] = None

    print 'Listening on port ', port

  def serve(self):
    while True:
      try:
        inputready,outputready,exceptready = select.select(self.servers.keys(), [], [], 0)
      except e:
        print e
        break

      for socket in inputready:
        if socket == self.server:
          client, address = socket.accept()
          self.recvConnection(client, address)
        else:
          try:
            data = socket.recv(2048)
            if data:
              if self.servers[socket].ready:
                self.recvData(socket, data)
              else:
                self.recvHandshake(socket, data)
            else:
              self.dropConnection(socket)
          except:
            self.dropConnection(socket)

      time.sleep(0.05)

      for client in self.servers.keys():
        if client != self.server:
          frame = self.servers[client].popFrameBuffer()
          if frame != None:
            self.handler[frame.opcode](client, frame)

    self.server.close()

  def dropConnection(self, client):
    print '%d hung up' % client.fileno()
    client.close()
    del self.servers[client]
  
  def recvConnection(self, client, address):
    print 'New connection %d from %s' % (client.fileno(), address)
    self.servers[client] = WSClient(address)
  
  def recvHandshake(self, client, data):
    response = self.servers[client].recvHandshake(data)
    client.send(response)
  
  def recvData(self, client, data):
    self.servers[client].recvData(data)
    
  def sendPing(self, client):
    frame          = WSFrame()
    frame.final    = 1
    frame.opcode   = 9
    frame.complete = True
    client.send(frame.toString())
    self.servers[client].ping = time.time()

  def h1(self, client, frame):
    for socket in self.servers.keys():
      if self.servers[socket] != None and socket != client and self.servers[socket].path == self.servers[client].path:
        socket.send(frame.toString())

  def h8(self, client, frame):
    client.send(frame.toString())
    self.dropConnection(client)

  def h9(self, client, frame):
    frame.opcode = 10
    client.send(frame.toString())

  def hA(self, client, frame):
    self.servers[client].pong = time.time()

  def hX(self, client, frame):
    pass

if __name__ == "__main__":
  WSServer().serve()
