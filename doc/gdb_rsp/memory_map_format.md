# Memory Map Format (Debugging with GDB)

---

### E.17 Memory Map Format

To be able to write into flash memory, GDB needs to obtain a memory map from the
target. This section describes the format of the memory map.

The memory map is obtained using the ‘`qXfer:memory-map:read`’ (see [qXfer
memory map read](about:blank/General-Query-Packets.html#qXfer-memory-map-read))
packet and is an XML document that lists memory regions.

GDB must be linked with the Expat library to support XML memory maps. See
[Expat](about:blank/Requirements.html#Expat).

The top-level structure of the document is shown below:

```
<?xml version="1.0"?>
<!DOCTYPE memory-map
          PUBLIC "+//IDN gnu.org//DTD GDB Memory Map V1.0//EN"
                 "http://sourceware.org/gdb/gdb-memory-map.dtd">
<memory-map>
    region...
</memory-map>
```

Each region can be either:

- A region of RAM starting at addr and extending for length bytes from there:

  ```
  <memory type="ram" start="addr" length="length"/>
  ```
- A region of read-only memory:

  ```
  <memory type="rom" start="addr" length="length"/>
  ```
- A region of flash memory, with erasure blocks blocksize bytes in length:

  ```
  <memory type="flash" start="addr" length="length">
    <property name="blocksize">blocksize</property>
  </memory>
  ```

Regions must not overlap. GDB assumes that areas of memory not covered by the
memory map are RAM, and uses the ordinary ‘`M`’ and ‘`X`’ packets to write to
addresses in such ranges.

The formal DTD for memory map format is given below:

```
<!-- ................................................... -->
<!-- Memory Map XML DTD ................................ -->
<!-- File: memory-map.dtd .............................. -->
<!-- .................................... .............. -->
<!-- memory-map.dtd -->
<!-- memory-map: Root element with versioning -->
<!ELEMENT memory-map (memory)*>
<!ATTLIST memory-map    version CDATA   #FIXED  "1.0.0">
<!ELEMENT memory (property)*>
<!-- memory: Specifies a memory region,
             and its type, or device. -->
<!ATTLIST memory        type    (ram|rom|flash) #REQUIRED
                        start   CDATA   #REQUIRED
                        length  CDATA   #REQUIRED>
<!-- property: Generic attribute tag -->
<!ELEMENT property (#PCDATA | property)*>
<!ATTLIST property      name    (blocksize) #REQUIRED>
```

---