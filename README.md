# gdbstub_cpp

a c++20 gdb rsp server library, focused on lldb

## build

```bash
cmake -G Ninja -B build-release
cmake --build build-release --parallel
```

## test

```bash
ctest --test-dir build-release --output-on-failure
```

## toy server

```bash
./build-release/bin/gdbstub_tool --listen 127.0.0.1:5555 --arch 32 --mode polling
```

Modes: `blocking`, `polling`, `async`.

## lldb (interactive)

If you are using the toy server, set a default arch and connect:

```bash
lldb -O "settings set target.default-arch riscv32" -O "gdb-remote 127.0.0.1:5555"
```

To enable RSP packet logging:

```bash
lldb -O "log enable gdb-remote packets" -O "gdb-remote 127.0.0.1:5555"
```

To log into a file:

```bash
lldb -O "log enable -f /tmp/lldb-gdb-remote.log gdb-remote packets" -O "gdb-remote 127.0.0.1:5555"
```

## format

```bash
cmake --build build-release --target gdbstub_cpp-format
```
