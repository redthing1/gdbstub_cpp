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

## format

```bash
cmake --build build-release --target gdbstub_cpp-format
```
