# Overview (Debugging with GDB)

---

### E.1 Overview

There may be occasions when you need to know something about the protocol--for
example, if there is only one serial port to your target machine, you might want
your program to do something special if it recognizes a packet meant for GDB.

In the examples below, ‘`->`’ and ‘`<-`’ are used to indicate transmitted and
received data, respectively.

All GDB commands and responses (other than acknowledgments and notifications,
see [Notification
Packets](about:blank/Notification-Packets.html#Notification-Packets)) are sent
as a packet. A packet is introduced with the character ‘`$`’, the actual
packet-data, and the terminating character ‘`#`’ followed by a two-digit
checksum:

```
$packet-data#checksum
```

The two-digit checksum is computed as the modulo 256 sum of all characters
between the leading ‘`$`’ and the trailing ‘`#`’ (an eight bit unsigned
checksum).

Implementors should note that prior to GDB 5.0 the protocol specification also
included an optional two-digit sequence-id:

```
$sequence-id:packet-data#checksum
```

That sequence-id was appended to the acknowledgment. GDB has never output
sequence-ids. Stubs that handle packets added since GDB 5.0 must not accept
sequence-id.

When either the host or the target machine receives a packet, the first response
expected is an acknowledgment: either ‘`+`’ (to indicate the package was
received correctly) or ‘`-`’ (to request retransmission):

```
-> $packet-data#checksum
<- +
```

The ‘`+`’/‘`-`’ acknowledgments can be disabled once a connection is
established. See [Packet
Acknowledgment](about:blank/Packet-Acknowledgment.html#Packet-Acknowledgment),
for details.

The host (GDB) sends commands, and the target (the debugging stub incorporated
in your program) sends a response. In the case of step and continue commands,
the response is only sent when the operation has completed, and the target has
again stopped all threads in all attached processes. This is the default
all-stop mode behavior, but the remote protocol also supports GDB’s non-stop
execution mode; see [Remote
Non-Stop](about:blank/Remote-Non_002dStop.html#Remote-Non_002dStop), for
details.

packet-data consists of a sequence of characters with the exception of ‘`#`’ and
‘`$`’ (see ‘`X`’ packet for additional exceptions).

Fields within the packet should be separated using ‘`,`’ ‘`;`’ or ‘`:`’. Except
where otherwise noted all numbers are represented in HEX with leading zeros
suppressed.

Implementors should note that prior to GDB 5.0, the character ‘`:`’ could not
appear as the third character in a packet (as it would potentially conflict with
the sequence-id).

Binary data in most packets is encoded as two hexadecimal digits per byte of
binary data. This allowed the traditional remote protocol to work over
connections which were only seven-bit clean. Some packets designed more recently
assume an eight-bit clean connection, and use a more efficient encoding to send
and receive binary data.

The binary data representation uses `7d` (ASCII ‘`}`’) as an escape character.
Any escaped byte is transmitted as the escape character followed by the original
character XORed with `0x20`. For example, the byte `0x7d` would be transmitted
as the two bytes `0x7d 0x5d`. The bytes `0x23` (ASCII ‘`#`’), `0x24` (ASCII
‘`$`’), and `0x7d` (ASCII ‘`}`’) must always be escaped. Responses sent by the
stub must also escape `0x2a` (ASCII ‘`*`’), so that it is not interpreted as the
start of a run-length encoded sequence (described next).

Response data can be run-length encoded to save space. Run-length encoding
replaces runs of identical characters with one instance of the repeated
character, followed by a ‘`*`’ and a repeat count. The repeat count is itself
sent encoded, to avoid binary characters in data: a value of n is sent as
`n+29`. For a repeat count greater or equal to 3, this produces a printable
ASCII character, e.g. a space (ASCII code 32) for a repeat count of 3. (This is
because run-length encoding starts to win for counts 3 or more.) Thus, for
example, ‘`0*` ’ is a run-length encoding of “0000”: the space character after
‘`*`’ means repeat the leading `0` `32 - 29 = 3` more times.

The printable characters ‘`#`’ and ‘`$`’ or with a numeric value greater than
126 must not be used. Runs of six repeats (‘`#`’) or seven repeats (‘`$`’) can
be expanded using a repeat count of only five (‘`"`’). For example, ‘`00000000`’
can be encoded as ‘`0*"00`’.

See [Standard Replies](about:blank/Standard-Replies.html#Standard-Replies), for
standard error responses, and how to respond indicating a command is not
supported.

In describing packets (commands and responses), each description has a template
showing the overall syntax, followed by an explanation of the packet’s meaning.
We include spaces in some of the templates for clarity; these are not part of
the packet’s syntax. No GDB packet uses spaces to separate its components. For
example, a template like ‘`foo bar baz`’ describes a packet beginning with the
three ASCII bytes ‘`foo`’, followed by a bar, followed directly by a baz. GDB
does not transmit a space character between the ‘`foo`’ and the bar, or between
the bar and the baz.

We place optional portions of a packet in [square brackets]; for example, a
template like ‘`c [addr]`’ describes a packet beginning with the single ASCII
character ‘`c`’, possibly followed by an addr.

At a minimum, a stub is required to support the ‘`?`’ command to tell GDB the
reason for halting, ‘`g`’ and ‘`G`’ commands for register access, and the ‘`m`’
and ‘`M`’ commands for memory access. Stubs that only control single-threaded
targets can implement run control with the ‘`c`’ (continue) command, and if the
target architecture supports hardware-assisted single-stepping, the ‘`s`’ (step)
command. Stubs that support multi-threading targets should support the ‘`vCont`’
command. All other commands are optional.

---