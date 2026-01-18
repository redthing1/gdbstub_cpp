# Remote Non-Stop (Debugging with GDB)

---

### E.11 Remote Protocol Support for Non-Stop Mode

GDB’s remote protocol supports non-stop debugging of multi-threaded programs, as
described in [Non-Stop
Mode](about:blank/Non_002dStop-Mode.html#Non_002dStop-Mode). If the stub
supports non-stop mode, it should report that to GDB by including ‘`QNonStop+`’
in its ‘`qSupported`’ response (see
[qSupported](about:blank/General-Query-Packets.html#qSupported)).

GDB typically sends a ‘`QNonStop`’ packet only when establishing a new
connection with the stub. Entering non-stop mode does not alter the state of any
currently-running threads, but targets must stop all threads in any
already-attached processes when entering all-stop mode. GDB uses the ‘`?`’
packet as necessary to probe the target state after a mode change.

In non-stop mode, when an attached process encounters an event that would
otherwise be reported with a stop reply, it uses the asynchronous notification
mechanism (see [Notification
Packets](about:blank/Notification-Packets.html#Notification-Packets)) to inform
GDB. In contrast to all-stop mode, where all threads in all processes are
stopped when a stop reply is sent, in non-stop mode only the thread reporting
the stop event is stopped. That is, when reporting a ‘`S`’ or ‘`T`’ response to
indicate completion of a step operation, hitting a breakpoint, or a fault, only
the affected thread is stopped; any other still-running threads continue to run.
When reporting a ‘`W`’ or ‘`X`’ response, all running threads belonging to other
attached processes continue to run.

In non-stop mode, the target shall respond to the ‘`?`’ packet as follows.
First, any incomplete stop reply notification/‘`vStopped`’ sequence in progress
is abandoned. The target must begin a new sequence reporting stop events for all
stopped threads, whether or not it has previously reported those events to GDB.
The first stop reply is sent as a synchronous reply to the ‘`?`’ packet, and
subsequent stop replies are sent as responses to ‘`vStopped`’ packets using the
mechanism described above. The target must not send asynchronous stop reply
notifications until the sequence is complete. If all threads are running when
the target receives the ‘`?`’ packet, or if the target is not attached to any
process, it shall respond ‘`OK`’.

If the stub supports non-stop mode, it should also support the ‘`swbreak`’ stop
reason if software breakpoints are supported, and the ‘`hwbreak`’ stop reason if
hardware breakpoints are supported (see [swbreak stop
reason](about:blank/Stop-Reply-Packets.html#swbreak-stop-reason)). This is
because given the asynchronous nature of non-stop mode, between the time a
thread hits a breakpoint and the time the event is finally processed by GDB, the
breakpoint may have already been removed from the target. Due to this, GDB needs
to be able to tell whether a trap stop was caused by a delayed breakpoint event,
which should be ignored, as opposed to a random trap signal, which should be
reported to the user. Note the ‘`swbreak`’ feature implies that the target is
responsible for adjusting the PC when a software breakpoint triggers, if
necessary, such as on the x86 architecture.

---