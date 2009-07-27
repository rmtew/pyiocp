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

from ctypes import windll, pythonapi
from ctypes import c_bool, c_char, c_char_p, c_ubyte, c_int, c_uint, c_short, c_ushort, c_long, c_ulong, c_void_p
from ctypes import Structure, Union, py_object, POINTER, pointer, sizeof, byref, create_string_buffer, cast
from ctypes.wintypes import HANDLE, ULONG, DWORD, BOOL, LPCSTR, LPCWSTR, WinError, WORD

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
        ("channel",         py_object),
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

import stackless
import weakref
import socket as stdsocket # We need the "socket" name for the function we export.

wsaData = WSADATA()
ret = WSAStartup(MAKEWORD(2, 2), LP_WSADATA(wsaData))
if ret != 0:
    raise WinError(ret)

hIOCP = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL_HANDLE, NULL, NULL)
if hIOCP == 0:
    WSACleanup()
    raise WinError()


CancelIo = windll.kernel32.CancelIo
CancelIo.argtypes = (HANDLE,)
CancelIo.restype = BOOL

managerRunning = False

def ManageSockets():
    global managerRunning

    try:
        _DispatchIOCP()
    except KeyboardInterrupt:
        _CleanupActiveIO()
        raise

    managerRunning = False

def StartManager():
    global managerRunning
    if not managerRunning:
        managerRunning = True
        stackless.tasklet(ManageSockets)()

_manage_sockets_func = StartManager

def stacklesssocket_manager(mgr):
    global _manage_sockets_func
    _manage_sockets_func = mgr

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
getnameinfo.argtypes = (POINTER(sockaddr), socklen_t, c_char_p, DWORD, c_char_p, DWORD, c_int)
getnameinfo.restype = c_int

NI_MAXHOST = 1025
NI_NUMERICHOST = 0x02

class socket:
    def __init__(self, family=AF_INET, type=SOCK_STREAM, proto=IPPROTO_TCP):    
        ret = WSASocket(family, type, proto, None, 0, WSA_FLAG_OVERLAPPED)
        if ret == INVALID_SOCKET:
            raise WinError()

        self._family = family
        self._type = type
        self._proto = proto
        self._timeout = 0

        # Bind the socket to the shared IO completion port.
        CreateIoCompletionPort(ret, hIOCP, NULL, NULL)

        self._socket = ret

        self.recvBuffer = None
        self.sendBuffer = (WSABUF * 1)()

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

    def bind(self, address):
        host, port = address

        sa = sockaddr_in()
        sa.sin_family = AF_INET
        sa.sin_addr.S_addr = inet_addr(host)
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
        c = ovAccept.channel = stackless.channel()

        acceptSocket = socket()

        ret = AcceptEx(self._socket, acceptSocket._socket, outputBuffer, dwReceiveDataLength, dwLocalAddressLength, dwRemoteAddressLength, byref(dwBytesReceived), byref(ovAccept))
        if ret == FALSE:
            err = WSAGetLastError()
            # The operation was successful and is currently in progress.  Ignore this error...
            if err != ERROR_IO_PENDING:
                closesocket(acceptSocket._socket)
                raise WinError(err)

        # Block until the overlapped operation completes.
        activeIO[self._socket] = c
        c.receive()

        localSockaddr = sockaddr_in()
        localSockaddrSize = c_int(sizeof(sockaddr_in))
        remoteSockaddr = sockaddr_in()
        remoteSockaddrSize = c_int(sizeof(sockaddr_in))

        GetAcceptExSockaddrs(outputBuffer, dwReceiveDataLength, dwLocalAddressLength, dwRemoteAddressLength, byref(localSockaddr), byref(localSockaddrSize), byref(remoteSockaddr), byref(remoteSockaddrSize))

        #hostbuf = create_string_buffer(NI_MAXHOST)
        #servbuf = c_char_p()
        #
        #xxx = cast(byref(localSockaddr), sockaddrp)
        #ret = getnameinfo(xxx, sizeof(sockaddr_in), hostbuf, sizeof(hostbuf), servbuf, 0, NI_NUMERICHOST)
        #if ret != 0:
        #    err = WSAGetLastError()
        #    closesocket(acceptSocket._socket)
        #    raise WinError(err)

        host = inet_ntoa(localSockaddr.sin_addr)
        port = ntohs(localSockaddr.sin_port)

        return (acceptSocket, (host, port))

    def recv(self, byteCount, flags=0):
        if self.recvBuffer is None:
            self.recvBuffer = (WSABUF * 1)()
            self.recvBuffer[0].buf = ' ' * READ_BUFFER_SIZE
            self.recvBuffer[0].len = READ_BUFFER_SIZE

        # WARNING: For now, we cap the readable amount to size of the preallocated buffer.
        byteCount = min(byteCount, READ_BUFFER_SIZE)
    
        numberOfBytesRecvd = DWORD()
        flags = DWORD()
        ovRecv = OVERLAPPED()
        c = ovRecv.channel = stackless.channel()

        ret = WSARecv(self._socket, cast(self.recvBuffer, POINTER(WSABUF)), 1, byref(numberOfBytesRecvd), byref(flags), byref(ovRecv), 0)
        if ret != 0:
            err = WSAGetLastError()
            # The operation was successful and is currently in progress.  Ignore this error...
            if err != ERROR_IO_PENDING:
                raise WinError(err)    

        # Block until the overlapped operation completes.
        activeIO[self._socket] = c
        numberOfBytes = c.receive()
        return self.recvBuffer[0].buf[:numberOfBytes]

    def send(self, data):
        self.sendBuffer[0].buf = data
        self.sendBuffer[0].len = len(data)

        bytesSent = DWORD()
        ovSend = OVERLAPPED()
        c = ovSend.channel = stackless.channel()

        ret = WSASend(self._socket, cast(self.sendBuffer, POINTER(WSABUF)), 1, byref(bytesSent), 0, byref(ovSend), 0)
        if ret != 0:
            err = WSAGetLastError()
            # The operation was successful and is currently in progress.  Ignore this error...
            if err != ERROR_IO_PENDING:
                Cleanup()
                raise WinError(err)    

        # Return the number of bytes that were send.
        activeIO[self._socket] = c
        return c.receive()

activeIO = weakref.WeakValueDictionary()

def _DispatchIOCP():
    numberOfBytes = DWORD()
    completionKey = c_ulong()
    ovCompletedPtr = POINTER(OVERLAPPED)()

    while True:
        while True:
            # Yield to give other tasklets a chance to be scheduled.
            stackless.schedule()

            ret = GetQueuedCompletionStatus(hIOCP, byref(numberOfBytes), byref(completionKey), byref(ovCompletedPtr), 50)
            if ret == FALSE:
                err = WSAGetLastError()
                if err == WAIT_TIMEOUT:
                    continue

                ovCompletedPtr.contents.channel.send_exception(WinError, err)
                continue

            break

        # Handle the completed packet.
        ovCompletedPtr.contents.channel.send(numberOfBytes.value)

def _CleanupActiveIO():
    for k, v in activeIO.items():
        ret = CancelIo(k)
        if ret == 0:
            raise WinError()

        # Any tasklets blocked on IO are killed silently.
        v.send_exception(TaskletExit)

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
    StartManager()

    print "STARTED"
    stackless.tasklet(Run)()
    stackless.run()
    print "EXITED"
