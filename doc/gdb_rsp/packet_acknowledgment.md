# Packet Acknowledgment (Debugging with GDB)

---

### E.12 Packet Acknowledgment

By default, when either the host or the target machine receives a packet, the
first response expected is an acknowledgment: either ‘`+`’ (to indicate the
package was received correctly) or ‘`-`’ (to request retransmission). This
mechanism allows the GDB remote protocol to operate over unreliable transport
mechanisms, such as a serial line.

In cases where the transport mechanism is itself reliable (such as a pipe or TCP
connection), the ‘`+`’/‘`-`’ acknowledgments are redundant. It may be desirable
to disable them in that case to reduce communication overhead, or for other
reasons. This can be accomplished by means of the ‘`QStartNoAckMode`’ packet;
see [QStartNoAckMode](about:blank/General-Query-Packets.html#QStartNoAckMode).

When in no-acknowledgment mode, neither the stub nor GDB shall send or expect
‘`+`’/‘`-`’ protocol acknowledgments. The packet and response format still
includes the normal checksum, as described in
[Overview](about:blank/Overview.html#Overview), but the checksum may be ignored
by the receiver.

If the stub supports ‘`QStartNoAckMode`’ and prefers to operate in
no-acknowledgment mode, it should report that to GDB by including
‘`QStartNoAckMode+`’ in its response to ‘`qSupported`’; see
[qSupported](about:blank/General-Query-Packets.html#qSupported). If GDB also
supports ‘`QStartNoAckMode`’ and it has not been disabled via the `set remote
noack-packet off` command (see [Remote
Configuration](about:blank/Remote-Configuration.html#Remote-Configuration)), GDB
may then send a ‘`QStartNoAckMode`’ packet to the stub. Only then may the stub
actually turn off packet acknowledgments. GDB sends a final ‘`+`’ acknowledgment
of the stub’s ‘`OK`’ response, which can be safely ignored by the stub.

Note that `set remote noack-packet` command only affects negotiation between GDB
and the stub when subsequent connections are made; it does not affect the
protocol acknowledgment state for any current connection. Since ‘`+`’/‘`-`’
acknowledgments are enabled by default when a new connection is established,
there is also no protocol request to re-enable the acknowledgments for the
current connection, once disabled.

---