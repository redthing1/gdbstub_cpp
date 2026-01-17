# Traceframe Info Format (Debugging with GDB)

---

### E.19 Traceframe Info Format

To be able to know which objects in the inferior can be examined when inspecting
a tracepoint hit, GDB needs to obtain the list of memory ranges, registers and
trace state variables that have been collected in a traceframe.

This list is obtained using the ‘`qXfer:traceframe-info:read`’ (see [qXfer
traceframe info
read](about:blank/General-Query-Packets.html#qXfer-traceframe-info-read)) packet
and is an XML document.

GDB must be linked with the Expat library to support XML traceframe info
discovery. See [Expat](about:blank/Requirements.html#Expat).

The top-level structure of the document is shown below:

```
<?xml version="1.0"?>
<!DOCTYPE traceframe-info
          PUBLIC "+//IDN gnu.org//DTD GDB Memory Map V1.0//EN"
                 "http://sourceware.org/gdb/gdb-traceframe-info.dtd">
<traceframe-info>
   block...
</traceframe-info>
```

Each traceframe block can be either:

- A region of collected memory starting at addr and extending for length bytes from there:

  ```
  <memory start="addr" length="length"/>
  ```
- A block indicating trace state variable numbered number has been collected:

  ```
  <tvar id="number"/>
  ```

The formal DTD for the traceframe info format is given below:

```
<!ELEMENT traceframe-info  (memory | tvar)* >
<!ATTLIST traceframe-info  version CDATA   #FIXED  "1.0">

<!ELEMENT memory        EMPTY>
<!ATTLIST memory        start   CDATA   #REQUIRED
                        length  CDATA   #REQUIRED>
<!ELEMENT tvar>
<!ATTLIST tvar          id      CDATA   #REQUIRED>
```