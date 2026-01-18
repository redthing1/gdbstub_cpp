# Branch Trace Configuration Format (Debugging with GDB)

---

### E.21 Branch Trace Configuration Format

For each inferior thread, GDB can obtain the branch trace configuration using
the ‘`qXfer:btrace-conf:read`’ (see [qXfer btrace-conf
read](about:blank/General-Query-Packets.html#qXfer-btrace_002dconf-read))
packet.

The configuration describes the branch trace format and configuration settings
for that format. The following information is described:

`bts`
:   This thread uses the *Branch Trace Store* (BTS) format.

    `size`
    :   The size of the BTS ring buffer in bytes.

`pt`
:   This thread uses the *Intel Processor Trace* (Intel PT) format.

    `size`
    :   The size of the Intel PT ring buffer in bytes.

GDB must be linked with the Expat library to support XML branch trace
configuration discovery. See [Expat](about:blank/Requirements.html#Expat).

The formal DTD for the branch trace configuration format is given below:

```
<!ELEMENT btrace-conf		(bts?, pt?)>
<!ATTLIST btrace-conf		version	CDATA	#FIXED "1.0">

<!ELEMENT bts	EMPTY>
<!ATTLIST bts	size		CDATA	#IMPLIED>

<!ELEMENT pt	EMPTY>
<!ATTLIST pt	size		CDATA	#IMPLIED>
<!ATTLIST pt	ptwrite		(yes | no)	#IMPLIED>
<!ATTLIST pt	event-tracing	(yes | no)	#IMPLIED>
```