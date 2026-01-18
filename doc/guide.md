# gdbstub_cpp C++ Usage Guide

This guide focuses on how to use the C++ API to build a Remote Serial Protocol (RSP)
server around your own target. It is intentionally practical and end-user oriented:
what to implement, how the pieces fit together, and how to extend support for more
features as your target grows.

The library does not provide an emulator, register database, or operating system
abstractions. You bring those. **gdbstub_cpp** supplies the RSP server, a small capability
model, and a transport abstraction.

---

## 1. Mental model

At a high level, you wire three things together:

```
RSP client <-> transport <-> server <-> target capabilities
```

- **transport**: how bytes move between the server and the remote client.
- **server**: parses/constructs RSP packets and dispatches them to your code.
- **target capabilities**: tiny objects that let the server read/write registers,
  memory, and control execution.

The server is non-templated and type-erased. Your target is built from capability
objects and stored behind a `target_view` that consists of function pointers plus
a context pointer. This makes the server stable and easy to embed.

---

## 2. Core building blocks (C++ API)

Include one header to get the public API:

```cpp
#include "gdbstub/gdbstub.hpp"
```

Key types:

- `gdbstub::target` and `gdbstub::make_target(...)` (see `src/gdbstub/target.hpp`)
- `gdbstub::arch_spec` (see `src/gdbstub/server.hpp`)
- `gdbstub::server`
- `gdbstub::transport` and `gdbstub::transport_tcp`
- RSP data types (stop/restart enums, `resume_request`, `stop_reason`, etc.)

---

## 3. Quickstart (a minimal server)

This is the minimal shape of a working integration: implement three required
capabilities (registers, memory, run control), build a `target`, provide an
`arch_spec`, and run a server over TCP.

```cpp
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "gdbstub/gdbstub.hpp"

struct DemoRegs {
  static constexpr int kRegCount = 16;
  std::array<uint64_t, kRegCount> regs{};

  size_t reg_size(int regno) const {
    if (regno < 0 || regno >= kRegCount) {
      return 0;
    }
    return sizeof(uint64_t);
  }

  gdbstub::target_status read_reg(int regno, std::span<std::byte> out) {
    if (regno < 0 || regno >= kRegCount || out.size() != sizeof(uint64_t)) {
      return gdbstub::target_status::invalid;
    }
    std::memcpy(out.data(), &regs[regno], sizeof(uint64_t));
    return gdbstub::target_status::ok;
  }

  gdbstub::target_status write_reg(int regno, std::span<const std::byte> data) {
    if (regno < 0 || regno >= kRegCount || data.size() != sizeof(uint64_t)) {
      return gdbstub::target_status::invalid;
    }
    std::memcpy(&regs[regno], data.data(), sizeof(uint64_t));
    return gdbstub::target_status::ok;
  }
};

struct DemoMem {
  std::vector<std::byte> mem;

  explicit DemoMem(size_t size) : mem(size) {}

  gdbstub::target_status read_mem(uint64_t addr, std::span<std::byte> out) {
    if (addr + out.size() > mem.size()) {
      return gdbstub::target_status::fault;
    }
    std::memcpy(out.data(), mem.data() + addr, out.size());
    return gdbstub::target_status::ok;
  }

  gdbstub::target_status write_mem(uint64_t addr, std::span<const std::byte> data) {
    if (addr + data.size() > mem.size()) {
      return gdbstub::target_status::fault;
    }
    std::memcpy(mem.data() + addr, data.data(), data.size());
    return gdbstub::target_status::ok;
  }
};

struct DemoRun {
  gdbstub::resume_result resume(const gdbstub::resume_request& request) {
    // Minimal behavior: always stop immediately.
    gdbstub::stop_reason stop;
    stop.kind = gdbstub::stop_kind::signal;
    stop.signal = 5; // generic stop

    gdbstub::resume_result result;
    result.state = gdbstub::resume_result::state::stopped;
    result.stop = stop;
    result.status = gdbstub::target_status::ok;
    return result;
  }
};

int main() {
  DemoRegs regs;
  DemoMem mem(64 * 1024);
  DemoRun run;

  auto target = gdbstub::make_target(regs, mem, run);

  gdbstub::arch_spec arch;
  arch.reg_count = DemoRegs::kRegCount;
  arch.pc_reg_num = 15;  // pick the register you use as PC
  arch.target_xml = "<target>...</target>"; // provide real XML
  arch.xml_arch_name = "demo";

  auto transport = std::make_unique<gdbstub::transport_tcp>();
  gdbstub::server server(target, arch, std::move(transport));
  server.listen("127.0.0.1:5555");
  server.serve_forever();
  return 0;
}
```

This example is intentionally minimal: the run capability always reports a stop
immediately. For real targets, you will implement execution, stop reporting,
and optional features.

---

## 4. The capability model

The library uses *capability objects* rather than inheritance. Each capability is
identified by the presence of a small set of methods.

Required capabilities (must be provided):
- **regs**: register access
- **mem**: memory access
- **run**: execution control

Optional capabilities (provide any you can):
- **breakpoints**
- **threads**
- **memory_layout**
- **host**
- **process**
- **shlib**
- **register_info**

### 4.1 `make_target` and capability discovery

`gdbstub::make_target(...)` is a variadic template that accepts the required
capability objects followed by any number of optional capability objects.

```cpp
auto target = gdbstub::make_target(regs, mem, run, breakpoints, threads, layout);
```

Important details:
- The required objects are checked at compile time by C++20 concepts.
- Optional capability objects are also detected by concepts.
- Each optional capability can be provided at most once.

**Design implication:** optional capability objects must *not* also implement the
required capability method signatures. If you have a single class that implements
everything, split it into small adapters (even if they just forward to the same
underlying object). The toy target in `src/gdbstub_tool/toy` is a good example
of this composition style.

---

## 5. Required capabilities in depth

### 5.1 Register access (`regs`)

Signature requirements:

```cpp
size_t reg_size(int regno);
gdbstub::target_status read_reg(int regno, std::span<std::byte> out);
gdbstub::target_status write_reg(int regno, std::span<const std::byte> data);
```

Semantics:
- `regno` is the register number used by the server (0..reg_count-1).
- `reg_size` returns the size in bytes for that register.
- `read_reg` must fill the whole output buffer.
- `write_reg` must consume the whole input buffer.

Guidance:
- If a register is unavailable, return size 0. The server treats size 0 as
  invalid for single-register access and skips it in bulk reads.
- Ensure `reg_count` and your target XML or register_info use the same ordering
  and sizes.
- Use `swap_register_endianness` in `arch_spec` if your internal register storage
  uses opposite endianness from the RSP representation. The server will reverse
  bytes per register on both read and write.

### 5.2 Memory access (`mem`)

Signature requirements:

```cpp
gdbstub::target_status read_mem(uint64_t addr, std::span<std::byte> out);
gdbstub::target_status write_mem(uint64_t addr, std::span<const std::byte> data);
```

Semantics:
- Reads and writes are *all-or-nothing*. If you cannot satisfy the full request,
  return an error status.
- The server clamps read requests to 2048 bytes internally.
- Write size is determined by the incoming packet; the server expects exact size
  matches and will reject malformed packets before calling you.

Recommended status usage:
- `ok`: success
- `fault`: address not mapped or access fault
- `invalid`: malformed request or unsupported size
- `unsupported`: explicit refusal of optional feature (rare for mem)

### 5.3 Run control (`run`)

Signature requirements:

```cpp
gdbstub::resume_result resume(const gdbstub::resume_request& request);
```

`resume_request` fields:
- `action`: `cont`, `step`, or `range_step`
- `direction`: `forward` or `reverse`
- `addr`: optional resume address (set PC to this before resuming)
- `signal`: optional signal value
- `range`: optional address range for `range_step`

`resume_result` fields:
- `state`: `running`, `stopped`, or `exited`
- `stop`: a `stop_reason` that explains the stop
- `exit_code`: optional exit code
- `status`: `ok`, `fault`, `invalid`, `unsupported`

Typical patterns:
- **Blocking execution**: do the run inside `resume()` and return a `stopped`
  result when you stop.
- **Non-blocking execution**: return `running`, then report stops later via
  `poll_stop()` or `set_stop_notifier()` (see below).

Optional run-related methods (strongly recommended):

```cpp
void interrupt();
std::optional<gdbstub::stop_reason> poll_stop();
void set_stop_notifier(gdbstub::stop_notifier notifier);
std::optional<gdbstub::run_capabilities> capabilities();
```

How the server uses them:
- `interrupt()` is called when the client sends an interrupt or when a non-stop
  stop request arrives.
- `poll_stop()` is called during `server::poll()` when the target is running.
- `set_stop_notifier()` is invoked when a connection is established and cleared
  on shutdown. Call the notifier when your run loop detects an async stop.
- `capabilities()` advertises optional features (reverse, range_step, non-stop).

If you do not implement `poll_stop()` or `set_stop_notifier()`, then `resume()`
should block until a stop and return `stopped`. Otherwise the server will never
receive a stop notification for a running target.

---

## 6. `arch_spec` and architecture description

`arch_spec` describes register layout and target characteristics. It is required
for a correct and useful RSP session.

```cpp
struct arch_spec {
  std::string target_xml;
  std::string xml_arch_name;
  std::string osabi;
  int reg_count = 0;
  int pc_reg_num = -1;
  std::optional<int> address_bits;
  bool swap_register_endianness = false;
};
```

Field details:
- **target_xml**: target description XML. This is how a client knows your register
  set and layout. If empty, the server will not advertise the XML capability.
- **xml_arch_name**: an identifier used when advertising the XML set. Must be
  non-empty to enable XML support.
- **reg_count**: total number of registers (0..reg_count-1). The server uses
  this to iterate registers and validate indices.
- **pc_reg_num**: register number containing the program counter. Used in stop
  replies and for certain metadata requests. Set to -1 if not available.
- **address_bits**: address space width in bits. Used for memory region info
  calculations when the target provides a memory map.
- **swap_register_endianness**: reverse byte order for each register on read/write.

Notes:
- `osabi` is currently not consumed by the server core. You can embed it in
  target XML or keep it for your own logic.
- If `address_bits` is not set, the server may infer it from optional host/process
  info (if provided). If none are available, it assumes a full 64-bit space.

---

## 7. Server lifecycle and control flow

Construct and run a server:

```cpp
auto target = gdbstub::make_target(...);

// Fill arch_spec correctly.
gdbstub::arch_spec arch{...};

auto transport = std::make_unique<gdbstub::transport_tcp>();
gdbstub::server server(target, arch, std::move(transport));

server.listen("127.0.0.1:5555");
server.serve_forever();
```

Key methods:
- `listen(address)`: bind and listen (transport-specific).
- `wait_for_connection()`: accept a connection and install the stop notifier.
- `has_connection()`: returns connection state.
- `serve_forever()`: blocking loop built on `poll()`.
- `poll(timeout)`: non-blocking (or timed) processing. Returns true if any events
  were processed.
- `notify_stop(stop_reason)`: enqueue a stop from outside the server thread.
- `stop()`: close transport and clear notifier.

### Polling integration

If you need to integrate with your own event loop, call `poll()` regularly:

```cpp
while (server.has_connection()) {
  server.poll(std::chrono::milliseconds(10));
  // Your other work...
}
```

`poll()` does two main things:
- Processes incoming packets and dispatches to your target.
- Checks for asynchronous stops (via `poll_stop()` and queued notifications).

---

## 8. Optional capabilities in depth

### 8.1 Breakpoints

Required methods if you implement breakpoints:

```cpp
gdbstub::target_status set_breakpoint(const gdbstub::breakpoint_spec& spec);
gdbstub::target_status remove_breakpoint(const gdbstub::breakpoint_spec& spec);
```

Optional capability query:

```cpp
std::optional<gdbstub::breakpoint_capabilities> capabilities();
```

`breakpoint_spec` fields:
- `type`: software/hardware/watchpoint
- `addr`: address
- `length`: size (interpretation depends on breakpoint type)

Behavior notes:
- If you return `unsupported`, the server replies with an empty response for
  optional features.
- If you do not provide `capabilities()`, the server assumes software breakpoints
  are supported and advertises only that.

### 8.2 Threads

Required methods if you implement thread support:

```cpp
std::vector<uint64_t> thread_ids();
uint64_t current_thread();
gdbstub::target_status set_current_thread(uint64_t tid);
std::optional<uint64_t> thread_pc(uint64_t tid);
std::optional<std::string> thread_name(uint64_t tid);
std::optional<gdbstub::stop_reason> thread_stop_reason(uint64_t tid);
```

Guidance:
- Thread IDs are 64-bit opaque values. Keep them stable for the duration of a
  session.
- `thread_ids()` should include the current thread.
- Return `std::nullopt` for `thread_pc`, `thread_name`, or `thread_stop_reason`
  when unknown.
- If you do not provide threads, the server will report a default thread ID of 1.

### 8.3 Memory layout

You may implement either or both of these:

```cpp
std::optional<gdbstub::memory_region_info> region_info(uint64_t addr);
std::vector<gdbstub::memory_region> memory_map();
```

Details:
- `region_info` returns a mapping or `nullopt` if the address is unknown.
- `memory_map` returns all known regions. The server can synthesize `region_info`
  from the map and will also describe unmapped gaps.

`memory_region` fields:
- `start`, `size`
- `perms` (bitmask of read/write/exec)
- optional `name`, optional `types`

If you provide a map but not `region_info`, the server will:
- Find the region containing the address, or
- Infer the size of the unmapped gap up to the next region or the end of address
  space (based on `arch_spec.address_bits`).

### 8.4 Host, process, and shared library metadata

These are purely informational and are only used if you provide them:

```cpp
std::optional<gdbstub::host_info> get_host_info();
std::optional<gdbstub::process_info> get_process_info();
std::optional<gdbstub::shlib_info> get_shlib_info();
std::optional<gdbstub::offsets_info> get_offsets_info();
```

You can omit them entirely if you do not have meaningful data. The server will
silently omit the corresponding features.

### 8.5 Register info

```cpp
std::optional<gdbstub::register_info> get_register_info(int regno);
```

`register_info` fields include:
- name, alternate name
- bitsize
- offset (byte offset within the register file)
- encoding and format
- set, generic name
- GCC/DWARF numbers
- container/invalidate register lists

Server behavior:
- If `bitsize` is 0, the server substitutes `reg_size(regno) * 8`.
- If `offset` is not provided, the server computes it by summing register sizes
  from 0..regno-1.
- If `encoding` or `format` are empty, the server defaults to `uint` and `hex`.

---

## 9. Execution reporting and stop reasons

### 9.1 `stop_reason`

`stop_reason` identifies why execution stopped:

```cpp
struct stop_reason {
  stop_kind kind = stop_kind::signal;
  int signal = 0;
  uint64_t addr = 0;
  int exit_code = 0;
  std::optional<uint64_t> thread_id;
  std::optional<replay_log_boundary> replay_log;
};
```

Guidelines:
- Use `stop_kind::exited` when the target is done; set `exit_code`.
- Use `sw_break` / `hw_break` / `watch_*` for breakpoint-related stops.
- Provide `thread_id` if you have threads; otherwise the server will choose one.

### 9.2 Running vs stopped states

How the server reacts to `resume_result`:
- `state::running`: server transitions to running and expects a later stop.
- `state::stopped`: server sends a stop reply immediately.
- `state::exited`: server sends an exit reply.

If you return `running`, you *must* later deliver a stop via one of:
- `poll_stop()` returning a stop reason
- `set_stop_notifier()` calling the notifier
- Explicit call to `server.notify_stop()` from your own code

---

## 10. Transport layer

`transport` is a simple interface. Implement it if you want a non-TCP transport.

```cpp
class transport {
public:
  virtual ~transport() = default;
  virtual bool listen(std::string_view address) = 0;
  virtual bool accept() = 0;
  virtual bool connected() const = 0;
  virtual bool readable(std::chrono::milliseconds timeout) = 0;
  virtual std::ptrdiff_t read(std::span<std::byte> out) = 0;
  virtual std::ptrdiff_t write(std::span<const std::byte> data) = 0;
  virtual void disconnect() = 0;
  virtual void close() = 0;
};
```

Expected behavior:
- `readable(timeout)` should block up to `timeout` and return true when data is
  available. Return false if not readable or not connected.
- `read()` returns bytes read. Return <= 0 to indicate disconnection.
- `write()` returns bytes written. Return <= 0 to indicate disconnection.
- `disconnect()` closes the current connection, `close()` also tears down
  any listening sockets or resources.

`transport_tcp` implements this interface and supports:
- `host:port` and `[ipv6]:port` addresses
- `*` as the host to bind to all interfaces

---

## 11. Common integration patterns

### 11.1 Component-based target composition

This is the easiest way to avoid capability conflicts and keep code clean:

```cpp
struct Regs { /* reg_size/read_reg/write_reg */ };
struct Mem { /* read_mem/write_mem */ };
struct Run { /* resume + optional interrupt/poll/notify */ };
struct Breakpoints { /* set/remove + optional caps */ };

Regs regs;
Mem mem;
Run run;
Breakpoints bps;

auto target = gdbstub::make_target(regs, mem, run, bps);
```

### 11.2 Single owner, multiple adapters

If you already have a monolithic target type, create thin adapters so optional
capabilities do not also implement required methods (a compile-time rule):

```cpp
struct CoreTarget { /* everything */ };
struct RegsAdapter { CoreTarget& t; /* reg methods */ };
struct MemAdapter { CoreTarget& t; /* mem methods */ };
struct RunAdapter { CoreTarget& t; /* run methods */ };
struct ThreadsAdapter { CoreTarget& t; /* thread methods */ };

CoreTarget core;
RegsAdapter regs{core};
MemAdapter mem{core};
RunAdapter run{core};
ThreadsAdapter threads{core};

auto target = gdbstub::make_target(regs, mem, run, threads);
```

### 11.3 Asynchronous stop reporting

When your run loop is in another thread, capture the notifier and call it when
you detect a stop:

```cpp
struct Run {
  std::atomic<bool> running{false};
  gdbstub::stop_notifier notifier{};

  void set_stop_notifier(gdbstub::stop_notifier n) { notifier = n; }

  gdbstub::resume_result resume(const gdbstub::resume_request&) {
    running.store(true);
    return gdbstub::resume_result{.state = gdbstub::resume_result::state::running};
  }

  void on_stop_detected(uint64_t tid) {
    if (notifier.notify) {
      gdbstub::stop_reason reason;
      reason.kind = gdbstub::stop_kind::signal;
      reason.signal = 5;
      reason.thread_id = tid;
      notifier(reason);
    }
  }
};
```

### 11.4 Poll-based stop reporting

If your target advances in small increments, implement `poll_stop()` and keep
`resume()` non-blocking:

```cpp
struct Run {
  std::atomic<bool> running{false};

  gdbstub::resume_result resume(const gdbstub::resume_request&) {
    running.store(true);
    return gdbstub::resume_result{.state = gdbstub::resume_result::state::running};
  }

  std::optional<gdbstub::stop_reason> poll_stop() {
    if (!running.load()) {
      return std::nullopt;
    }
    if (/* detected stop */) {
      running.store(false);
      gdbstub::stop_reason reason;
      reason.kind = gdbstub::stop_kind::signal;
      reason.signal = 5;
      return reason;
    }
    return std::nullopt;
  }
};
```

---

## 12. Performance and limits

- Packet buffer size is fixed at 4096 bytes for incoming packets.
- Memory reads are clamped to 2048 bytes per request.
- Bulk register writes (`G`) require the exact concatenated size of all registers.

If you have very large register files or need large memory transfers, consider:
- minimizing register count and size where possible
- optimizing your read/write routines for contiguous requests

---

## 13. Troubleshooting and common pitfalls

**Register access issues**
- If `reg_count` does not match your register definitions, bulk reads/writes
  will fail or misalign.
- If `reg_size(regno)` returns 0 for a register that you advertise in target XML
  or register_info, the client may see inconsistent data.
- If PC register number (`pc_reg_num`) is wrong, stop replies will report an
  incorrect PC.

**No stops while running**
- If `resume()` returns `running` but you do not implement `poll_stop()` or
  `set_stop_notifier()`, the server will never learn that execution stopped.
- If `interrupt()` is missing, interrupt requests will have no effect.

**Memory map confusion**
- If you provide a memory map but no `address_bits`, the server may assume a
  huge unmapped region size when queried at unmapped addresses.

**Unexpected empty replies**
- The server responds with empty replies for optional features that are not
  supported or not advertised. If you expect a feature to work, make sure
  you provided the matching capability object and that its methods return
  `ok` instead of `unsupported`.

---

## 14. Quick reference (capability checklist)

Required capabilities:
- regs: `reg_size`, `read_reg`, `write_reg`
- mem: `read_mem`, `write_mem`
- run: `resume`

Optional capabilities:
- breakpoints: `set_breakpoint`, `remove_breakpoint`, optional `capabilities`
- threads: `thread_ids`, `current_thread`, `set_current_thread`, `thread_pc`,
  `thread_name`, `thread_stop_reason`
- memory_layout: `region_info` and/or `memory_map`
- host: `get_host_info`
- process: `get_process_info`
- shlib: `get_shlib_info`
- register_info: `get_register_info`

Optional run helpers (strongly recommended):
- `interrupt`
- `poll_stop`
- `set_stop_notifier`
- `capabilities`

---

## 15. Minimal integration checklist

1) Implement `regs`, `mem`, and `run` capability objects.
2) Build a `target` with `make_target(regs, mem, run)`.
3) Create an `arch_spec` with correct `reg_count`, `pc_reg_num`, and `target_xml`.
4) Create a `transport` (`transport_tcp` or your own).
5) Construct `server`, call `listen`, then `serve_forever` or `poll`.
6) Add optional capabilities as you need richer features.

---

## 16. Where to look next

- `src/gdbstub/target.hpp`: capability definitions and `make_target`.
- `src/gdbstub/server.hpp` and `src/gdbstub/server.cpp`: full server behavior.
- `src/gdbstub_tool/toy`: a complete C++ example with many optional capabilities.

This guide should be sufficient to build a clean, fully functional integration
using the C++ API alone. If you want a deeper dive on any specific capability or
pattern, expand that section with target-specific details and examples.
