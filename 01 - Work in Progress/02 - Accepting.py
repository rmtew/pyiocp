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

wsaData = WSADATA()
ret = WSAStartup(MAKEWORD(2, 2), LP_WSADATA(wsaData))
if ret != 0:
    raise WinError(ret)

AF_INET = 2
SOCK_STREAM = 1
IPPROTO_TCP = 6
WSA_FLAG_OVERLAPPED = 0x01
INVALID_SOCKET = ~0

ret = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, None, 0, WSA_FLAG_OVERLAPPED)
if ret == INVALID_SOCKET:
    WSACleanup()
    raise WinError()

listenSocket = ret

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

hIOCP = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL_HANDLE, NULL, NULL)
if hIOCP == 0:
    err = WSAGetLastError()
    closesocket(listenSocket)
    WSACleanup()
    raise WinError(err)

# Bind the listen socket to the IO completion port.
CreateIoCompletionPort(listenSocket, hIOCP, NULL, NULL)

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

class _UN(Structure):
    _fields_ = [
        ("s_un_b",          _UN_b),
        ("s_un_w",          _UN_w),
        ("s_addr",          c_ulong),
    ]

class in_addr(Union):
    _fields_ = [
        ("s_un",            _UN),
    ]
    _anonymous_ = ("s_un",)

class sockaddr_in(Structure):
    _fields_ = [
        ("sin_family",      c_short),
        ("sin_port",        c_ushort),
        ("sin_addr",        in_addr),
        ("szDescription",   c_char * 8),
    ]

sockaddr_inp = POINTER(sockaddr_in)

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

htons = windll.Ws2_32.htons
htons.argtypes = (c_ushort,)
htons.restype = c_ushort

hostdata = gethostbyname("")
#ip = inet_ntoa(cast(hostdata.contents.h_addr_list, POINTER(in_addr)).contents)

port = 10101
ip = "127.0.0.1"

sa = sockaddr_in()
sa.sin_family = AF_INET
sa.sin_addr.S_addr = inet_addr(ip)
sa.sin_port = htons(port)

SOCKET_ERROR = -1

ret = bind(listenSocket, sockaddr_inp(sa), sizeof(sa))
if ret == SOCKET_ERROR:
    closesocket(listenSocket)
    CloseHandle(hIOCP)
    WSACleanup()
    raise WinError()

listen = windll.Ws2_32.listen
listen.argtypes = (SOCKET, c_int)
listen.restype = BOOL

SOMAXCONN = 0x7fffffff

ret = listen(listenSocket, SOMAXCONN)
if ret != 0:
    closesocket(listenSocket)
    CloseHandle(hIOCP)
    WSACleanup()
    raise WinError()

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

ret = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, None, 0, WSA_FLAG_OVERLAPPED)
if ret == INVALID_SOCKET:
    err = WSAGetLastError()
    closesocket(listenSocket)
    CloseHandle(hIOCP)
    WSACleanup()
    raise WinError(err)

acceptSocket = ret

FALSE = 0
ERROR_IO_PENDING = 997

dwReceiveDataLength = 0
dwLocalAddressLength = sizeof(sockaddr_in) + 16
dwRemoteAddressLength = sizeof(sockaddr_in) + 16
outputBuffer = create_string_buffer(dwReceiveDataLength + dwLocalAddressLength + dwRemoteAddressLength)
dwBytesReceived = DWORD()
ovAccept = OVERLAPPED()
ovAccept.channel = "accept"

ret = AcceptEx(listenSocket, acceptSocket, outputBuffer, dwReceiveDataLength, dwLocalAddressLength, dwRemoteAddressLength, byref(dwBytesReceived), byref(ovAccept))
if ret == FALSE:
    err = WSAGetLastError()
    # The operation was successful and is currently in progress.  Ignore this error...
    if err != ERROR_IO_PENDING:
        closesocket(acceptSocket)
        closesocket(listenSocket)
        CloseHandle(hIOCP)
        WSACleanup()
        raise WinError(err)

# Bind the accept socket to the IO completion port.
CreateIoCompletionPort(acceptSocket, hIOCP, NULL, NULL)

GetQueuedCompletionStatus = windll.kernel32.GetQueuedCompletionStatus
GetQueuedCompletionStatus.argtypes = (HANDLE, POINTER(DWORD), POINTER(c_ulong), POINTER(POINTER(OVERLAPPED)), DWORD)
GetQueuedCompletionStatus.restype = BOOL

numberOfBytes = DWORD()
completionKey = c_ulong()
ovCompletedPtr = POINTER(OVERLAPPED)()

ret = GetQueuedCompletionStatus(hIOCP, byref(numberOfBytes), byref(completionKey), byref(ovCompletedPtr), 10000)
if ret == FALSE:
    err = WSAGetLastError()
    closesocket(acceptSocket)
    closesocket(listenSocket)
    CloseHandle(hIOCP)
    WSACleanup()
    raise WinError(err)

class WSABUF(Structure):
    _fields_ = [
        ("len",         c_ulong),
        ("buf",         c_char_p),
    ]

WSASend = windll.Ws2_32.WSASend
WSASend.argtypes = (SOCKET, POINTER(WSABUF), DWORD, POINTER(DWORD), DWORD, POINTER(OVERLAPPED), c_void_p)
WSASend.restype = c_int

msg = "Disconnecting you.."
sendBuffer = (WSABUF * 1)()
sendBuffer[0].buf = msg
sendBuffer[0].len = len(msg)
bytesSent = DWORD()
ovSend = OVERLAPPED()
ovSend.channel = "send"
ret = WSASend(acceptSocket, cast(sendBuffer, POINTER(WSABUF)), 1, byref(bytesSent), 0, byref(ovSend), 0)
if ret != 0:
    err = WSAGetLastError()
    # The operation was successful and is currently in progress.  Ignore this error...
    if err != ERROR_IO_PENDING:
        closesocket(acceptSocket)
        closesocket(listenSocket)
        CloseHandle(hIOCP)
        WSACleanup()
        raise WinError(err)    

ret = GetQueuedCompletionStatus(hIOCP, byref(numberOfBytes), byref(completionKey), byref(ovCompletedPtr), 10000)
if ret == FALSE:
    err = WSAGetLastError()
    closesocket(acceptSocket)
    closesocket(listenSocket)
    CloseHandle(hIOCP)
    WSACleanup()
    raise WinError(err)

if ovCompletedPtr.contents.channel == ovSend.channel:
    print "SUCCESS"
else:
    print "FAILURE: Unrecognised overlapped object"

closesocket(acceptSocket)
closesocket(listenSocket)
CloseHandle(hIOCP)
WSACleanup()
