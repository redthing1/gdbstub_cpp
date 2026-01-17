# Standard Replies (Debugging with GDB)

---

### E.2 Standard Replies

The remote protocol specifies a few standard replies. All commands support
these, except as noted in the individual command descriptions.

empty response
:   An empty response (raw character sequence ‘`$#00`’) means the command is not
    supported by the stub. This way it is possible to extend the protocol. A newer
    GDB can tell if a command is supported based on that response (but see also
    [qSupported](about:blank/General-Query-Packets.html#qSupported)).

‘`E xx`’
:   An error has occurred; xx is a two-digit hexadecimal error number. In almost all
    cases, the protocol does not specify the meaning of the error numbers; GDB
    usually ignores the numbers, or displays them to the user without further
    interpretation.

‘`E.errtext`’
:   An error has occurred; errtext is the textual error message, encoded in ASCII.