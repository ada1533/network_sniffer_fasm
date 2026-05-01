format PE console
entry start

include 'include/win32ax.inc'

AF_INET            = 2
SOCK_RAW           = 3
IPPROTO_IP         = 0
SIO_RCVALL         = 0x98000001
RCVALL_ON          = 1
SOCKET_ERROR       = -1
INVALID_SOCKET     = -1
MAX_PACKET         = 65535

IP_PROTOCOL        = 9
IP_SRC_ADDR        = 12
IP_DST_ADDR        = 16

SIZEOF_SOCKADDR_IN = 16

section '.data' data readable writeable

wsa_data         db 400 dup(0)
sock             dd 0
local_addr       db SIZEOF_SOCKADDR_IN dup(0)
sys_time         SYSTEMTIME
recv_buf         db MAX_PACKET dup(0)
bytes_returned   dd 0
rcvall_flag      dd RCVALL_ON

szTitle          db '============================================',13,10
                 db '  FASM Network Sniffer (printf edition)',13,10
                 db '  (Run as Administrator!)',13,10
                 db '============================================',13,10
                 db '  Time         | Proto | Source -> Dest          | Size',13,10
                 db '--------------------------------------------',13,10,0

szError_WSA      db 'Error: WSAStartup failed!',13,10,0
szError_Socket   db 'Error: Cannot create raw socket!',13,10
                 db '  Run as Administrator.',13,10,0
szError_Bind     db 'Error: bind() failed!',13,10,0
szError_IOCTL    db 'Error: WSAIoctl (SIO_RCVALL) failed!',13,10,0
szError_Host     db 'Error: gethostname failed!',13,10,0
szError_Resolve  db 'Error: Cannot resolve IP.',13,10,0

szListening      db 'Listening on IP: ',0
szStartCapture   db 13,10,'Packet capture started... (Ctrl+C to exit)',13,10,13,10,0

szTCP            db 'TCP  ',0
szUDP            db 'UDP  ',0
szICMP           db 'ICMP ',0
szIGMP           db 'IGMP ',0

fmt_s            db '%s',0
fmt_time         db '%02d:%02d:%02d.%03d',0
fmt_ip           db '%d.%d.%d.%d',0
fmt_proto_num    db '0x%02X ',0
fmt_size_line    db '%d bytes',13,10,0
fmt_sep          db ' | ',0
fmt_arrow        db ' -> ',0
fmt_nl           db 13,10,0

hostname_buf     db 256 dup(0)
packet_count     dd 0

section '.code' code readable executable

start:
        invoke   SetConsoleOutputCP, 65001

        cinvoke  printf, fmt_s, szTitle

        invoke   WSAStartup, 0x0202, wsa_data
        test     eax, eax
        jnz      .error_wsa

        invoke   gethostname, hostname_buf, 256
        test     eax, eax
        jnz      .error_host

        invoke   gethostbyname, hostname_buf
        test     eax, eax
        jz       .error_resolve

        mov      eax, [eax + 12]
        mov      eax, [eax]
        mov      eax, [eax]

        mov      word [local_addr], AF_INET
        mov      word [local_addr + 2], 0
        mov      dword [local_addr + 4], eax

        cinvoke  printf, fmt_s, szListening
        movzx    eax, byte [local_addr + 4]
        movzx    ebx, byte [local_addr + 5]
        movzx    ecx, byte [local_addr + 6]
        movzx    edx, byte [local_addr + 7]
        cinvoke  printf, fmt_ip, eax, ebx, ecx, edx
        cinvoke  printf, fmt_s, fmt_nl

        invoke   socket, AF_INET, SOCK_RAW, IPPROTO_IP
        cmp      eax, INVALID_SOCKET
        je       .error_socket
        mov      [sock], eax

        invoke   bind, [sock], local_addr, SIZEOF_SOCKADDR_IN
        cmp      eax, SOCKET_ERROR
        je       .error_bind

        invoke   WSAIoctl, [sock], SIO_RCVALL, rcvall_flag, 4, 0, 0, bytes_returned, 0, 0
        cmp      eax, SOCKET_ERROR
        je       .error_ioctl

        cinvoke  printf, fmt_s, szStartCapture

.capture_loop:
        invoke   recv, [sock], recv_buf, MAX_PACKET, 0
        cmp      eax, SOCKET_ERROR
        je       .capture_loop
        test     eax, eax
        jz       .capture_loop

        mov      esi, eax

        cmp      esi, 20
        jb       .capture_loop

        mov      al, byte [recv_buf]
        shr      al, 4
        cmp      al, 4
        jne      .capture_loop

        invoke   GetLocalTime, sys_time
        movzx    eax, word [sys_time.wHour]
        movzx    ebx, word [sys_time.wMinute]
        movzx    ecx, word [sys_time.wSecond]
        movzx    edx, word [sys_time.wMilliseconds]
        cinvoke  printf, fmt_time, eax, ebx, ecx, edx
        cinvoke  printf, fmt_s, fmt_sep

        movzx    eax, byte [recv_buf + IP_PROTOCOL]
        cmp      al, 1
        je       .p_icmp
        cmp      al, 2
        je       .p_igmp
        cmp      al, 6
        je       .p_tcp
        cmp      al, 17
        je       .p_udp
        jmp      .p_other

.p_tcp:
        cinvoke  printf, fmt_s, szTCP
        jmp      .show_addr
.p_udp:
        cinvoke  printf, fmt_s, szUDP
        jmp      .show_addr
.p_icmp:
        cinvoke  printf, fmt_s, szICMP
        jmp      .show_addr
.p_igmp:
        cinvoke  printf, fmt_s, szIGMP
        jmp      .show_addr
.p_other:
        movzx    eax, byte [recv_buf + IP_PROTOCOL]
        cinvoke  printf, fmt_proto_num, eax

.show_addr:
        cinvoke  printf, fmt_s, fmt_sep

        movzx    eax, byte [recv_buf + IP_SRC_ADDR]
        movzx    ebx, byte [recv_buf + IP_SRC_ADDR + 1]
        movzx    ecx, byte [recv_buf + IP_SRC_ADDR + 2]
        movzx    edx, byte [recv_buf + IP_SRC_ADDR + 3]
        cinvoke  printf, fmt_ip, eax, ebx, ecx, edx

        cinvoke  printf, fmt_s, fmt_arrow

        movzx    eax, byte [recv_buf + IP_DST_ADDR]
        movzx    ebx, byte [recv_buf + IP_DST_ADDR + 1]
        movzx    ecx, byte [recv_buf + IP_DST_ADDR + 2]
        movzx    edx, byte [recv_buf + IP_DST_ADDR + 3]
        cinvoke  printf, fmt_ip, eax, ebx, ecx, edx

        cinvoke  printf, fmt_s, fmt_sep

        cinvoke  printf, fmt_size_line, esi

        inc      dword [packet_count]
        jmp      .capture_loop

.error_wsa:
        cinvoke  printf, fmt_s, szError_WSA
        jmp      .exit

.error_host:
        cinvoke  printf, fmt_s, szError_Host
        jmp      .cleanup

.error_resolve:
        cinvoke  printf, fmt_s, szError_Resolve
        jmp      .cleanup

.error_socket:
        cinvoke  printf, fmt_s, szError_Socket
        jmp      .cleanup

.error_bind:
        cinvoke  printf, fmt_s, szError_Bind
        jmp      .cleanup

.error_ioctl:
        cinvoke  printf, fmt_s, szError_IOCTL
        jmp      .cleanup

.cleanup:
        invoke   closesocket, [sock]
        invoke   WSACleanup

.exit:
        invoke   ExitProcess, 0

section '.idata' import data readable

library kernel32, 'kernel32.dll',\
        ws2_32,   'ws2_32.dll',\
        msvcrt,   'msvcrt.dll'

import kernel32,\
        ExitProcess,        'ExitProcess',\
        GetLocalTime,       'GetLocalTime',\
        SetConsoleOutputCP, 'SetConsoleOutputCP'

import ws2_32,\
        WSAStartup,    'WSAStartup',\
        WSACleanup,    'WSACleanup',\
        WSAIoctl,      'WSAIoctl',\
        socket,        'socket',\
        bind,          'bind',\
        recv,          'recv',\
        closesocket,   'closesocket',\
        gethostname,   'gethostname',\
        gethostbyname, 'gethostbyname'

import msvcrt,\
        printf, 'printf'