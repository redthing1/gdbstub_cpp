# Interrupts (Debugging with GDB)

---

### E.9 Interrupts

In all-stop mode, when a program on the remote target is running, GDB may
attempt to interrupt it by sending a ‘`Ctrl-C`’, `BREAK` or a `BREAK` followed
by `g`, control of which is specified via GDB’s ‘`interrupt-sequence`’.

The precise meaning of `BREAK` is defined by the transport mechanism and may, in
fact, be undefined. GDB does not currently define a `BREAK` mechanism for any of
the network interfaces except for TCP, in which case GDB sends the `telnet`
BREAK sequence.

‘`Ctrl-C`’, on the other hand, is defined and implemented for all transport
mechanisms. It is represented by sending the single byte `0x03` without any of
the usual packet overhead described in the Overview section (see
[Overview](about:blank/Overview.html#Overview)). When a `0x03` byte is
transmitted as part of a packet, it is considered to be packet data and does
*not* represent an interrupt. E.g., an ‘`X`’ packet (see [X
packet](about:blank/Packets.html#X-packet)), used for binary downloads, may
include an unescaped `0x03` as part of its packet.

`BREAK` followed by `g` is also known as Magic SysRq g. When Linux kernel
receives this sequence from serial port, it stops execution and connects to gdb.

In non-stop mode, because packet resumptions are asynchronous (see [vCont
packet](about:blank/Packets.html#vCont-packet)), GDB is always free to send a
remote command to the remote stub, even when the target is running. For that
reason, GDB instead sends a regular packet (see [vCtrlC
packet](about:blank/Packets.html#vCtrlC-packet)) with the usual packet framing
instead of the single byte `0x03`.

Stubs are not required to recognize these interrupt mechanisms and the precise
meaning associated with receipt of the interrupt is implementation defined. If
the target supports debugging of multiple threads and/or processes, it should
attempt to interrupt all currently-executing threads and processes. If the stub
is successful at interrupting the running program, it should send one of the
stop reply packets (see [Stop Reply
Packets](about:blank/Stop-Reply-Packets.html#Stop-Reply-Packets)) to GDB as a
result of successfully stopping the program in all-stop mode, and a stop reply
for each stopped thread in non-stop mode. Interrupts received while the program
is stopped are queued and the program will be interrupted when it is resumed
next time.

---