#
#    Copyright 2009 Richard Tew <richard.m.tew@gmail.com>
#    This file is part of pyiocp.
#
#    pyiocp is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    pyiocp is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with pyiocp.  If not, see <http://www.gnu.org/licenses/>.
#

import stackless
import weakref
import socket as stdsocket # We need the "socket" name for the function we export.

##############################################################################
# Monkey-patching of this module in place of the original socket module.

def install():
    if stdsocket._realsocket is socket:
        raise StandardError("Still installed")
    stdsocket._realsocket = socket
    #stdsocket.socket = stdsocket.SocketType = stdsocket._socketobject = _socketobject_new

def uninstall():
    stdsocket._realsocket = _realsocket_old
    ##stdsocket.socket = stdsocket.SocketType = stdsocket._socketobject = _socketobject_old

_realsocket_old = stdsocket._realsocket
_socketobject_old = stdsocket._socketobject

##############################################################################

# If we are to masquerade as the socket module, we need to provide the constants.
if "__all__" in stdsocket.__dict__:
    __all__ = stdsocket.__dict__
    for k, v in stdsocket.__dict__.iteritems():
        if k in __all__:
            globals()[k] = v
        elif k == "EBADF":
            globals()[k] = v
else:
    for k, v in stdsocket.__dict__.iteritems():
        if k.upper() == k:
            globals()[k] = v
    error = stdsocket.error
    timeout = stdsocket.timeout
    # WARNING: this function blocks and is not thread safe.
    # The only solution is to spawn a thread to handle all
    # getaddrinfo requests.  Implementing a stackless DNS
    # lookup service is only second best as getaddrinfo may
    # use other methods.
    getaddrinfo = stdsocket.getaddrinfo

# urllib2 apparently uses this directly.  We need to cater for that.
_fileobject = stdsocket._fileobject

from ctypes import windll, pythonapi
from ctypes import c_bool, c_char, c_char_p, c_ubyte, c_int, c_uint, c_short, c_ushort, c_long, c_ulong, c_void_p
from ctypes import Structure, Union, py_object, POINTER, pointer, sizeof, byref, create_string_buffer, cast
from ctypes.wintypes import HANDLE, ULONG, DWORD, BOOL, LPCSTR, LPCWSTR, WinError, WORD, WINFUNCTYPE

WSADESCRIPTION_LEN = 256
WSASYS_STATUS_LEN = 128

class WSADATA(Structure):
    _fields_ = [
        ("wVersion",        WORD),
        ("wHighVersion",    WORD),
        ("szDescription",   c_char * (WSADESCRIPTION_LEN+1)),
        ("szSystemStatus",  c_char * (WSASYS_STATUS_LEN+1)),
        ("iMaxSockets",     c_ushort),
        ("iMaxUdpDg",       c_ushort),
        ("lpVendorInfo",    c_char_p),
    ]

LP_WSADATA = POINTER(WSADATA)

WSAStartup = windll.Ws2_32.WSAStartup
WSAStartup.argtypes = (WORD, POINTER(WSADATA))
WSAStartup.restype = c_int

WSACleanup = windll.Ws2_32.WSACleanup
WSACleanup.argtypes = ()
WSACleanup.restype = c_int

GROUP = c_uint
SOCKET = c_uint

WSASocket = windll.Ws2_32.WSASocketA
WSASocket.argtypes = (c_int, c_int, c_int, c_void_p, GROUP, DWORD)
WSASocket.restype = SOCKET

closesocket = windll.Ws2_32.closesocket
closesocket.argtypes = (SOCKET,)
closesocket.restype = c_int

def MAKEWORD(bLow, bHigh):
    return (bHigh << 8) + bLow

AF_INET = 2
SOCK_STREAM = 1
IPPROTO_TCP = 6
WSA_FLAG_OVERLAPPED = 0x01
INVALID_SOCKET = ~0

# Create an IO completion port.
CreateIoCompletionPort = windll.kernel32.CreateIoCompletionPort
CreateIoCompletionPort.argtypes = (HANDLE, HANDLE, c_ulong, DWORD)
CreateIoCompletionPort.restype = HANDLE

CloseHandle = windll.kernel32.CloseHandle
CloseHandle.argtypes = (HANDLE,)
CloseHandle.restype = BOOL

WSAGetLastError = windll.Ws2_32.WSAGetLastError

NULL = c_ulong()
INVALID_HANDLE_VALUE = HANDLE(-1)
NULL_HANDLE = HANDLE(0)

class _UN_b(Structure):
    _fields_ = [
        ("s_b1",            c_ubyte),
        ("s_b2",            c_ubyte),
        ("s_b3",            c_ubyte),
        ("s_b4",            c_ubyte),
    ]

class _UN_w(Structure):
    _fields_ = [
        ("s_w1",            c_ushort),
        ("s_w2",            c_ushort),
    ]

class in_addr(Union):
    _fields_ = [
        ("s_un_b",          _UN_b),
        ("s_un_w",          _UN_w),
        ("s_addr",          c_ulong),
    ]

class sockaddr_in(Structure):
    _fields_ = [
        ("sin_family",      c_short),
        ("sin_port",        c_ushort),
        ("sin_addr",        in_addr),
        ("szDescription",   c_char * 8),
    ]
    _anonymous_ = ("sin_addr",)

sockaddr_inp = POINTER(sockaddr_in)

class sockaddr(Structure):
    _fields_ = [
        ("sa_family",       c_short),
        ("sa_data",         c_char * 14),
    ]

sockaddrp = POINTER(sockaddr)

bind = windll.Ws2_32.bind
bind.argtypes = (SOCKET, sockaddr_inp, c_int)
bind.restype = c_int

class hostent(Structure):
    _fields_ = [
        ("h_name",          c_char_p),
        ("h_aliases",       POINTER(c_char_p)),
        ("h_addrtype",      c_short),
        ("h_length",        c_short),
        ("h_addr_list",     POINTER(c_char_p)),
    ]

hostentp = POINTER(hostent)

gethostbyname = windll.Ws2_32.gethostbyname
gethostbyname.argtypes = (c_char_p,)
gethostbyname.restype = hostentp

inet_addr = windll.Ws2_32.inet_addr
inet_addr.argtypes = (c_char_p,)
inet_addr.restype = c_ulong

inet_ntoa = windll.Ws2_32.inet_ntoa
inet_ntoa.argtypes = (in_addr,)
inet_ntoa.restype = c_char_p

ntohs = windll.Ws2_32.ntohs
ntohs.argtypes = (c_ushort,)
ntohs.restype = c_ushort

htons = windll.Ws2_32.htons
htons.argtypes = (c_ushort,)
htons.restype = c_ushort

SOCKET_ERROR = -1

class _US(Structure):
    _fields_ = [
        ("Offset",          DWORD),
        ("OffsetHigh",      DWORD),
    ]

class _U(Union):
    _fields_ = [
        ("s",               _US),
        ("Pointer",         c_void_p),
    ]
    _anonymous_ = ("s",)

class OVERLAPPED(Structure):
    _fields_ = [
        ("Internal",        POINTER(ULONG)),
        ("InternalHigh",    POINTER(ULONG)),
        ("u",               _U),
        ("hEvent",          HANDLE),
        # Custom fields.
        ("opID",            ULONG),
        ("label",           py_object),
    ]
    _anonymous_ = ("u",)

AcceptEx = windll.Mswsock.AcceptEx
AcceptEx.argtypes = (SOCKET, SOCKET, c_void_p, DWORD, DWORD, DWORD, POINTER(DWORD), POINTER(OVERLAPPED))
AcceptEx.restype = BOOL

FALSE = 0
ERROR_IO_PENDING = 997

GetQueuedCompletionStatus = windll.kernel32.GetQueuedCompletionStatus
GetQueuedCompletionStatus.argtypes = (HANDLE, POINTER(DWORD), POINTER(c_ulong), POINTER(POINTER(OVERLAPPED)), DWORD)
GetQueuedCompletionStatus.restype = BOOL

WAIT_TIMEOUT = 258

STATE_WRITING = 1
STATE_READING = 2

class WSABUF(Structure):
    _fields_ = [
        ("len",         c_ulong),
        ("buf",         c_char_p),
    ]

WSARecv = windll.Ws2_32.WSARecv
WSARecv.argtypes = (SOCKET, POINTER(WSABUF), DWORD, POINTER(DWORD), POINTER(DWORD), POINTER(OVERLAPPED), c_void_p)
WSARecv.restype = c_int

WSASend = windll.Ws2_32.WSASend
WSASend.argtypes = (SOCKET, POINTER(WSABUF), DWORD, POINTER(DWORD), DWORD, POINTER(OVERLAPPED), c_void_p)
WSASend.restype = c_int

CancelIo = windll.kernel32.CancelIo
CancelIo.argtypes = (HANDLE,)
CancelIo.restype = BOOL

READ_BUFFER_SIZE = 64 * 1024

"""
void GetAcceptExSockaddrs(
  __in   PVOID lpOutputBuffer,
  __in   DWORD dwReceiveDataLength,
  __in   DWORD dwLocalAddressLength,
  __in   DWORD dwRemoteAddressLength,
  __out  LPSOCKADDR *LocalSockaddr,
  __out  LPINT LocalSockaddrLength,
  __out  LPSOCKADDR *RemoteSockaddr,
  __out  LPINT RemoteSockaddrLength
);
"""

listen = windll.Ws2_32.listen
listen.argtypes = (SOCKET, c_int)
listen.restype = BOOL

GetAcceptExSockaddrs = windll.Mswsock.GetAcceptExSockaddrs
GetAcceptExSockaddrs.argtypes = (c_void_p, DWORD, DWORD, DWORD, POINTER(sockaddr_in), POINTER(c_int), POINTER(sockaddr_in), POINTER(c_int))
GetAcceptExSockaddrs.restype = c_int

setsockopt = windll.Ws2_32.setsockopt
setsockopt.argtypes = (SOCKET, c_int, c_int, c_char_p, c_int)
setsockopt.restype = c_int

"""
int WSAAPI getnameinfo(
  __in   const struct sockaddr FAR *sa,
  __in   socklen_t salen,
  __out  char FAR *host,
  __in   DWORD hostlen,
  __out  char FAR *serv,
  __in   DWORD servlen,
  __in   int flags
);
"""

socklen_t = c_int

getnameinfo = windll.Ws2_32.getnameinfo
getnameinfo.argtypes = (POINTER(sockaddr_in), socklen_t, c_char_p, DWORD, c_char_p, DWORD, c_int)
getnameinfo.restype = c_int

NI_MAXHOST = 1025
NI_NUMERICHOST = 0x02

"""
int WSAIoctl(
  __in   SOCKET s,
  __in   DWORD dwIoControlCode,
  __in   LPVOID lpvInBuffer,
  __in   DWORD cbInBuffer,
  __out  LPVOID lpvOutBuffer,
  __in   DWORD cbOutBuffer,
  __out  LPDWORD lpcbBytesReturned,
  __in   LPWSAOVERLAPPED lpOverlapped,
  __in   LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
);
"""

WSAIoctl = windll.Ws2_32.WSAIoctl
WSAIoctl.argtypes = (SOCKET, DWORD, c_void_p, DWORD, c_void_p, DWORD, POINTER(DWORD), POINTER(OVERLAPPED), c_void_p)
WSAIoctl.restype = c_int

IOC_OUT         = 0x40000000      
IOC_IN          = 0x80000000
IOC_INOUT       = (IOC_IN|IOC_OUT)

IOC_WS2         = 0x08000000

def _WSAIORW(x,y): return (IOC_INOUT|(x)|(y))

SIO_GET_EXTENSION_FUNCTION_POINTER = _WSAIORW(IOC_WS2,6)


class GUID(Structure):
    _fields_ = [
        ("Data1",           c_ulong),
        ("Data2",           c_ushort),
        ("Data3",           c_ushort),
        ("Data4",           c_ubyte * 8),
    ]

WSAID_CONNECTEX = GUID(0x25a207b9,0xddf3,0x4660, (c_ubyte * 8)(0x8e,0xe9,0x76,0xe5,0x8c,0x74,0x06,0x3e))

"""
BOOL PASCAL ConnectEx(
  __in      SOCKET s,
  __in      const struct sockaddr *name,
  __in      int namelen,
  __in_opt  PVOID lpSendBuffer,
  __in      DWORD dwSendDataLength,
  __out     LPDWORD lpdwBytesSent,
  __in      LPOVERLAPPED lpOverlapped
);
"""

ConnectExFunc = WINFUNCTYPE(BOOL, SOCKET, sockaddr_inp, c_int, c_void_p, DWORD, POINTER(DWORD), POINTER(OVERLAPPED))

class socket:
    def __init__(self, family=AF_INET, type=SOCK_STREAM, proto=IPPROTO_TCP):    
        StartManager()

        _socket = WSASocket(family, type, proto, None, 0, WSA_FLAG_OVERLAPPED)
        if _socket == INVALID_SOCKET:
            raise WinError()

        # Bind the socket to the shared IO completion port.
        CreateIoCompletionPort(_socket, hIOCP, _socket, NULL)

        self.wsFnConnectEx = ConnectExFunc()
        dwBytes = DWORD()
        ret = WSAIoctl(_socket, SIO_GET_EXTENSION_FUNCTION_POINTER, byref(WSAID_CONNECTEX), sizeof(WSAID_CONNECTEX), byref(self.wsFnConnectEx), sizeof(self.wsFnConnectEx), byref(dwBytes), cast(0, POINTER(OVERLAPPED)), 0)
        if ret == SOCKET_ERROR:
            err = WSAGetLastError()
            closesocket(ret)
            raise WinError(err)

        self._family = family
        self._type = type
        self._proto = proto
        self._timeout = 0

        self._socket = _socket
        activeSockets[_socket] = self

        self.recvBuffer = None
        self.sendBuffer = (WSABUF * 1)()
        
        self.opid = 0

    def __getnextopid(self):
        self.opid += 1
        return self.opid

    def fileno(self):
        return self._socket

    def getfamily(self):
        return self._family

    def gettype(self):
        return self._type

    def getproto(self):
        return self._proto

    def gettimeout(self):
        return self._timeout

    family = property(getfamily, doc="the socket family")
    type = property(gettype, doc="the socket type")
    proto = property(getproto, doc="the socket protocol")
    timeout = property(gettimeout, doc="the socket timeout")

    def setsockopt(self, level, optname, value):
        if type(value) is str:
            bufp = c_char_p(value)
            buflen = len(value)
        else:
            buf = c_int(value)
            bufp = cast(byref(buf), c_char_p)
            buflen = sizeof(c_int)

        ret = setsockopt(self._socket, level, optname, bufp, buflen);
        if ret == SOCKET_ERROR:
            raise WinError()

    def connect(self, address):
        host, port = address

        self.bind(("0.0.0.0", 0))

        sa = sockaddr_in()
        sa.sin_family = AF_INET
        sa.sin_addr.s_addr = inet_addr(host)
        sa.sin_port = htons(port)

        bytesSent = DWORD(0)
        ovConnect = OVERLAPPED()
        opID = ovConnect.opID = self.__getnextopid()
        c = stackless.channel()
        c.preference = 0
        ovConnect.label = "connect"

        activeOps[(self._socket, opID)] = (c, ovConnect)

        ret = self.wsFnConnectEx(self._socket, sa, sizeof(sa), 0, 0, NULL, byref(ovConnect))
        if ret == FALSE:
            err = WSAGetLastError()
            # The operation was successful and is currently in progress.  Ignore this error...
            if err != ERROR_IO_PENDING:
                raise WinError()
            
            c.receive()

    def bind(self, address):
        host, port = address

        sa = sockaddr_in()
        sa.sin_family = AF_INET
        sa.sin_addr.s_addr = inet_addr(host)
        sa.sin_port = htons(port)

        ret = bind(self._socket, sockaddr_inp(sa), sizeof(sa))
        if ret == SOCKET_ERROR:
            raise WinError()

    def listen(self, backlog):
        ret = listen(self._socket, backlog)
        if ret != 0:
            raise WinError()

    def accept(self):
        dwReceiveDataLength = 0
        dwLocalAddressLength = sizeof(sockaddr_in) + 16
        dwRemoteAddressLength = sizeof(sockaddr_in) + 16
        outputBuffer = create_string_buffer(dwReceiveDataLength + dwLocalAddressLength + dwRemoteAddressLength)

        dwBytesReceived = DWORD()
        ovAccept = OVERLAPPED()
        opID = ovAccept.opID = self.__getnextopid()
        c = stackless.channel()
        c.preference = 0
        ovAccept.label = "accept"

        acceptSocket = socket()

        activeOps[(self._socket, opID)] = (c, ovAccept)

        ret = AcceptEx(self._socket, acceptSocket._socket, outputBuffer, dwReceiveDataLength, dwLocalAddressLength, dwRemoteAddressLength, byref(dwBytesReceived), byref(ovAccept))
        if ret == FALSE:
            err = WSAGetLastError()
            # The operation was successful and is currently in progress.  Ignore this error...
            if err != ERROR_IO_PENDING:
                closesocket(acceptSocket._socket)
                raise WinError(err)

            # Block until the overlapped operation completes.
            c.receive()

        localSockaddr = sockaddr_in()
        localSockaddrSize = c_int(sizeof(sockaddr_in))
        remoteSockaddr = sockaddr_in()
        remoteSockaddrSize = c_int(sizeof(sockaddr_in))

        GetAcceptExSockaddrs(outputBuffer, dwReceiveDataLength, dwLocalAddressLength, dwRemoteAddressLength, byref(localSockaddr), byref(localSockaddrSize), byref(remoteSockaddr), byref(remoteSockaddrSize))

        hostbuf = create_string_buffer(NI_MAXHOST)
        servbuf = c_char_p()

        port = ntohs(localSockaddr.sin_port)

        localSockaddr.sin_family = AF_INET
        ret = getnameinfo(localSockaddr, sizeof(sockaddr_in), hostbuf, sizeof(hostbuf), servbuf, 0, NI_NUMERICHOST)
        if ret != 0:
            err = WSAGetLastError()
            closesocket(acceptSocket._socket)
            raise WinError(err)

        # host = inet_ntoa(localSockaddr.sin_addr)

        return (acceptSocket, (hostbuf.value, port))

    def recv(self, byteCount, flags=0):
        if self.recvBuffer is None:
            self.recvBuffer = (WSABUF * 1)()
            self.recvBuffer[0].buf = ' ' * READ_BUFFER_SIZE
            self.recvBuffer[0].len = READ_BUFFER_SIZE

        # WARNING: For now, we cap the readable amount to size of the preallocated buffer.
        byteCount = min(byteCount, READ_BUFFER_SIZE)
    
        dwNumberOfBytes = DWORD()
        flags = DWORD()
        ovRecv = OVERLAPPED()
        opID = ovRecv.opID = self.__getnextopid()
        c = stackless.channel()
        c.preference = 0
        ovRecv.label = "recv"

        activeOps[(self._socket, opID)] = (c, ovRecv)

        ret = WSARecv(self._socket, cast(self.recvBuffer, POINTER(WSABUF)), 1, byref(dwNumberOfBytes), byref(flags), byref(ovRecv), 0)
        if ret == SOCKET_ERROR:            
            err = WSAGetLastError()
            # The operation was successful and is currently in progress.  Ignore this error...
            if err != ERROR_IO_PENDING:
                raise WinError(err)    

            # Block until the overlapped operation completes.
            numberOfBytes = c.receive()
        else:
            numberOfBytes = dwNumberOfBytes.value
            
        return self.recvBuffer[0].buf[:numberOfBytes]

    def recvfrom(self, *args, **kwargs):
        raise NotImplemented

    def recv_into(self, *args, **kwargs):
        raise NotImplemented

    def recvfrom_into(self, *args, **kwargs):
        raise NotImplemented

    def send(self, data):
        self.sendBuffer[0].buf = data
        self.sendBuffer[0].len = len(data)

        bytesSent = DWORD()
        ovSend = OVERLAPPED()
        opID = ovSend.opID = self.__getnextopid()
        c = stackless.channel()
        c.preference = 0

        activeOps[(self._socket, opID)] = (c, ovSend)

        ret = WSASend(self._socket, cast(self.sendBuffer, POINTER(WSABUF)), 1, byref(bytesSent), 0, byref(ovSend), 0)
        if ret != SOCKET_ERROR:
            return bytesSent.value

        err = WSAGetLastError()
        # The operation was successful and is currently in progress.  Ignore this error...
        if err != ERROR_IO_PENDING:
            raise WinError(err)    

        # Return the number of bytes that were send.
        return c.receive()

    def sendto(self, *args, **kwargs):
        raise NotImplemented

    def sendall(self, msg, flags=None):
        bytesSent = self.send(msg)
        while bytesSent < len(msg):
            bytesSent += self.send(msg[bytesSent:])


activeOps = {}
activeSockets = weakref.WeakValueDictionary()

def _DispatchIOCP():
    numberOfBytes = DWORD()
    completionKey = c_ulong()
    ovCompletedPtr = POINTER(OVERLAPPED)()

    def _GetCompletionChannel(completionKey, overlappedPtr):
        _socket = completionKey.value
        opID = ovCompletedPtr.contents.opID
        k = _socket, opID
        c, ovRef = activeOps[k]
        del activeOps[k]

        return c

    # This may cause early exits.  It is meant to detect the case where socket
    # IO is being done on the main tasklet and the only other tasklet is this one
    # and to then stay alive.  Or something like that.
    while len(activeSockets) or stackless.runcount > 2:
        while True:
            # Yield to give other tasklets a chance to be scheduled.
            stackless.schedule()

            c = None
            ret = GetQueuedCompletionStatus(hIOCP, byref(numberOfBytes), byref(completionKey), byref(ovCompletedPtr), 50)
            if ret == FALSE:
                err = WSAGetLastError()
                if err == WAIT_TIMEOUT:
                    continue

                # This is a more general unexpected error, that the user should be made aware of.
                # Because the OVERLAPPED pointer may be NULL, we need to do this bool check.
                if not bool(ovCompletedPtr):
                    raise WinError(err)

                c = _GetCompletionChannel(completionKey, ovCompletedPtr)
                c.send_exception(WinError, err)
                continue

            break

        # Handle the completed packets for operations that did not complete immediately.
        # Operations that did complete immediately have no reason to be waiting on a channel.
        c = _GetCompletionChannel(completionKey, ovCompletedPtr)
        if c.balance == -1:
            c.send(numberOfBytes.value)

def _CleanupActiveIO():
    for (_socket, opID), (c, ovRef) in activeOps.items():
        ret = CancelIo(_socket)
        if ret == 0:
            raise WinError(err)

        # Any tasklets blocked on IO are killed silently.        
        if c.balance == -1:
            import traceback
            traceback.print_stack(c.queue.frame)

            c.send_exception(TaskletExit)

managerRunning = False
wsaStarted = False

def InitialiseSockets():
    global hIOCP, wsaStarted

    if not wsaStarted:
        wsaStarted = True

        wsaData = WSADATA()
        ret = WSAStartup(MAKEWORD(2, 2), LP_WSADATA(wsaData))
        if ret != 0:
            raise WinError(ret)

    hIOCP = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL_HANDLE, NULL, NULL)
    if hIOCP == 0:
        err = WSAGetLastError()
        WSACleanup()
        raise WinError(err)

def ManageSockets():
    global managerRunning
    try:
        _DispatchIOCP()
    finally:
        _CleanupActiveIO()
        CloseHandle(hIOCP)

    managerRunning = False

def StartManager():
    global managerRunning
    if not managerRunning:
        managerRunning = True

        InitialiseSockets()
        stackless.tasklet(ManageSockets)()

_manage_sockets_func = StartManager

def stacklesssocket_manager(mgr):
    global _manage_sockets_func
    _manage_sockets_func = mgr

SOL_SOCKET = 0xffff
SO_REUSEADDR = 0x0004

def Run():
    address = ("127.0.0.1", 3000)
    listenSocket = socket(AF_INET, SOCK_STREAM)
    listenSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    listenSocket.bind(address)
    listenSocket.listen(5)

    def handle_echo(_socket, _address):
        while True:
            data = currentSocket.recv(256)
            if data == "":
                print _address, "DISCONNECTED"
                return

            print _address, "READ", data, len(data)
            dlen = currentSocket.send(data)
            print _address, "ECHOD", dlen            

    while True:
        print "Waiting for new connection"
        currentSocket, clientAddress = listenSocket.accept()
        print "Connection", currentSocket.fileno(), "from", clientAddress
        
        stackless.tasklet(handle_echo)(currentSocket, clientAddress)

if __name__ == "__main__":
    print "STARTED"
    stackless.tasklet(Run)()
    stackless.run()
    print "EXITED"
