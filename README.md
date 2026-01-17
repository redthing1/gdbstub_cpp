# gdbstub_cpp

a c++20 gdb rsp server library, focused on lldb

## what

- a gdb remote serial protocol (rsp) server
- a neat, incremental api for wiring up to any sort of target (registers, memory, run control, breakpoints, threads, etc.)

## integration

1. implement the required capability objects: `regs`, `mem`, `run`.
2. optionally implement `breakpoints`, `threads`, `memory_layout`, `host`, `process`, `shlib`, `register_info`.
3. build an `arch_spec` (target xml + reg count + pc reg number).
4. create a `server` with `make_target(...)`, `arch_spec`, and a `transport`.
5. integrate with simple `serve_forever()`, or flexible async `poll()`.

here's a minimal sketch:

```cpp
auto target = gdbstub::make_target(regs, mem, run);
gdbstub::arch_spec arch{
  .target_xml = target_xml,
  .xml_arch_name = xml_arch_name,
  .osabi = osabi,
  .reg_count = reg_count,
  .pc_reg_num = pc_reg_num,
};

auto transport = std::make_unique<gdbstub::transport_tcp>();
gdbstub::server server(target, arch, std::move(transport));
server.listen("127.0.0.1:5555");
server.wait_for_connection();
server.serve_forever();
```

## build

```bash
cmake -G Ninja -B build-release
cmake --build build-release --parallel
```

## test

```bash
ctest --test-dir build-release --output-on-failure
```

## a sample target

see the full-featured demo target under `src/gdbstub_tool/toy/`.

run debug server:
```bash
./build-release/bin/gdbstub_tool --listen 127.0.0.1:5555 --arch 32 --mode polling
```

## lldb

connect with lldb:

```bash
lldb -O "gdb-remote 127.0.0.1:5555"
```

if disassembly looks wrong, set a default arch:
`settings set target.default-arch riscv32`

gdbstub_cpp serves `target.xml` and also supports lldb's `qRegisterInfo` fallback.
if the lldb build doesn't know the arch, you may still see registers but
disassembly/stack can be limited.

to enable RSP packet logging:

```bash
lldb -O "log enable gdb-remote packets" -O "gdb-remote 127.0.0.1:5555"
```

to log into a file:

```bash
lldb -O "log enable -f /tmp/lldb-gdb-remote.log gdb-remote packets" -O "gdb-remote 127.0.0.1:5555"
```

## reference

protocol specifications and documentation under [doc](./doc).
