#!/usr/bin/env python3

from __future__ import annotations

import argparse
import os
import queue
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional


@dataclass
class ProcessResult:
    proc: subprocess.Popen[str]
    output_queue: "queue.Queue[str]"
    thread: threading.Thread

    def terminate(self, timeout: float) -> None:
        if self.proc.poll() is not None:
            return
        self.proc.terminate()
        try:
            self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=timeout)

    def drain_output(self) -> str:
        lines: list[str] = []
        while True:
            try:
                lines.append(self.output_queue.get_nowait())
            except queue.Empty:
                break
        return "".join(lines)


@dataclass
class PacketEvent:
    direction: str
    payload: str


def start_process(args: list[str]) -> ProcessResult:
    proc = subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    assert proc.stdout is not None
    output_queue: "queue.Queue[str]" = queue.Queue()

    def reader() -> None:
        for line in proc.stdout:
            output_queue.put(line)

    thread = threading.Thread(target=reader, daemon=True)
    thread.start()
    return ProcessResult(proc=proc, output_queue=output_queue, thread=thread)


def next_available_port(host: str) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return int(sock.getsockname()[1])


def wait_for_output_line(
    result: ProcessResult, predicate: Callable[[str], bool], timeout: float
) -> Optional[str]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if result.proc.poll() is not None:
            return None
        try:
            line = result.output_queue.get(timeout=0.1)
        except queue.Empty:
            continue
        if predicate(line):
            return line
    return None


def build_lldb_commands(
    arch: str,
    host: str,
    port: int,
    log_path: str,
    reg_name: str,
    reg_value_hex: str,
) -> list[str]:
    return [
        f"settings set target.default-arch {arch}",
        f"log enable -f {log_path} gdb-remote packets",
        f"gdb-remote {host}:{port}",
        "register read",
        f"register write {reg_name} {reg_value_hex}",
        f"register read {reg_name}",
        "memory read --format x --count 4 0x1000",
        "breakpoint set --address 0x1008",
        "continue",
        "stepi",
        "thread list",
        "process detach",
    ]


def run_lldb(
    lldb_path: str,
    commands: list[str],
    timeout: float,
) -> subprocess.CompletedProcess[str]:
    args = [lldb_path, "-b"]
    for cmd in commands:
        args.extend(["-o", cmd])
    return subprocess.run(args, text=True, capture_output=True, timeout=timeout)


def parse_rsp_log(log_text: str) -> list[PacketEvent]:
    events: list[PacketEvent] = []
    pattern = re.compile(r"(send|read) packet: \$(.*)#([0-9A-Fa-f]{2})")
    for line in log_text.splitlines():
        match = pattern.search(line)
        if not match:
            continue
        events.append(PacketEvent(direction=match.group(1), payload=match.group(2)))
    return events


def unescape_rsp_binary(payload: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(payload):
        c = payload[i]
        if c == "}" and i + 1 < len(payload):
            out.append(chr(ord(payload[i + 1]) ^ 0x20))
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def has_event(
    events: list[PacketEvent], direction: str, predicate: Callable[[str], bool]
) -> bool:
    return any(
        event.direction == direction and predicate(event.payload) for event in events
    )


def response_after(
    events: list[PacketEvent],
    send_predicate: Callable[[str], bool],
    read_predicate: Callable[[str], bool],
) -> bool:
    for idx, event in enumerate(events):
        if event.direction != "send" or not send_predicate(event.payload):
            continue
        for response in events[idx + 1 :]:
            if response.direction == "read" and read_predicate(response.payload):
                return True
        return False
    return False


def require_output_match(
    pattern: str, stdout: str, label: str, errors: list[str]
) -> None:
    if not re.search(pattern, stdout, re.IGNORECASE):
        errors.append(f"missing output: {label}")


def check_lldb_output(stdout: str, reg_name: str, reg_value_hex: str) -> list[str]:
    errors: list[str] = []
    reg_value = reg_value_hex.lower().removeprefix("0x")
    require_output_match(r"\bpc\s*=\s*0x0*1000\b", stdout, "pc = 0x1000", errors)
    require_output_match(
        r"Breakpoint 1: address = 0x0*1008",
        stdout,
        "breakpoint address 0x1008",
        errors,
    )
    require_output_match(
        rf"\b{re.escape(reg_name)}\s*=\s*0x0*{re.escape(reg_value)}\b",
        stdout,
        f"{reg_name} = 0x{reg_value}",
        errors,
    )
    if "stop reason = breakpoint" not in stdout:
        errors.append("missing output: stop reason = breakpoint")
    if "thread #1" not in stdout:
        errors.append("missing output: thread #1")
    return errors


def check_rsp_log(log_text: str) -> list[str]:
    events = parse_rsp_log(log_text)
    errors: list[str] = []

    if not response_after(
        events,
        lambda payload: payload.startswith("qSupported"),
        lambda payload: "PacketSize=" in payload,
    ):
        errors.append("missing qSupported handshake")

    if not response_after(
        events,
        lambda payload: payload.startswith("qXfer:features:read:target.xml"),
        lambda payload: "<target" in payload,
    ):
        errors.append("missing target.xml response")

    if not has_event(
        events,
        "send",
        lambda payload: payload.startswith("g") or payload.startswith("p"),
    ):
        errors.append("missing register read packet")

    if not has_event(
        events,
        "send",
        lambda payload: payload.startswith("P") or payload.startswith("G"),
    ):
        errors.append("missing register write packet")

    if not has_event(
        events,
        "send",
        lambda payload: (payload.startswith("m") or payload.startswith("x"))
        and "," in payload,
    ):
        errors.append("missing memory read packet")

    if not response_after(
        events,
        lambda payload: payload.startswith("Z0,1008"),
        lambda payload: payload == "OK",
    ):
        errors.append("missing breakpoint response")

    if not response_after(
        events,
        lambda payload: payload == "c" or payload.startswith("vCont;c"),
        lambda payload: payload.startswith("T"),
    ):
        errors.append("missing stop reply after continue")

    if not (
        has_event(events, "send", lambda payload: payload.startswith("qfThreadInfo"))
        or has_event(events, "send", lambda payload: payload.startswith("jThreadsInfo"))
    ):
        errors.append("missing thread list request")

    if has_event(events, "send", lambda payload: payload.startswith("jThreadsInfo")):
        if not response_after(
            events,
            lambda payload: payload.startswith("jThreadsInfo"),
            lambda payload: unescape_rsp_binary(payload).startswith("["),
        ):
            errors.append("jThreadsInfo missing JSON response")

    if has_event(
        events, "send", lambda payload: payload.startswith("jThreadExtendedInfo:")
    ):
        if not response_after(
            events,
            lambda payload: payload.startswith("jThreadExtendedInfo:"),
            lambda payload: True,
        ):
            errors.append("missing response to jThreadExtendedInfo")

    for optional_packet in (
        "qStructuredDataPlugins",
        "qShlibInfoAddr",
        "qXfer:memory-map:read::",
    ):
        if has_event(
            events, "send", lambda payload, p=optional_packet: payload.startswith(p)
        ):
            if not response_after(
                events,
                lambda payload, p=optional_packet: payload.startswith(p),
                lambda payload: True,
            ):
                errors.append(f"missing response to {optional_packet}")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="LLDB end-to-end test for gdbstub_cpp")
    parser.add_argument("--lldb", required=True, help="Path to lldb executable")
    parser.add_argument("--gdbstub-tool", required=True, help="Path to gdbstub_tool")
    parser.add_argument("--arch", choices=["32", "64"], default="32")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--timeout", type=float, default=25.0)
    args = parser.parse_args()

    gdbstub_tool = os.path.abspath(args.gdbstub_tool)
    if not os.path.exists(gdbstub_tool):
        print(f"gdbstub_tool not found: {gdbstub_tool}")
        return 1

    arch_bits = int(args.arch)
    arch_name = "riscv32" if arch_bits == 32 else "riscv64"
    reg_name = "r1"
    reg_value_hex = "0x11223344" if arch_bits == 32 else "0x1122334455667788"

    port = next_available_port(args.host)
    tool_args = [
        gdbstub_tool,
        "--listen",
        f"{args.host}:{port}",
        "--arch",
        str(arch_bits),
        "--mode",
        "polling",
    ]

    tool_result = start_process(tool_args)
    ready_line = wait_for_output_line(
        tool_result, lambda line: "listening on" in line, timeout=5.0
    )
    if ready_line is None:
        tool_output = tool_result.drain_output()
        tool_result.terminate(timeout=5)
        print("gdbstub_tool did not start listening in time")
        if tool_output:
            print("--- gdbstub_tool output ---")
            print(tool_output)
        return 1

    with tempfile.TemporaryDirectory() as temp_dir:
        log_path = os.path.join(temp_dir, "lldb-gdb-remote.log")
        commands = build_lldb_commands(
            arch_name,
            args.host,
            port,
            log_path,
            reg_name,
            reg_value_hex,
        )

        try:
            lldb_result = run_lldb(args.lldb, commands, args.timeout)
        except subprocess.TimeoutExpired:
            lldb_result = None

        if lldb_result is None:
            success = False
            stdout = ""
            stderr = ""
        else:
            stdout = lldb_result.stdout
            stderr = lldb_result.stderr
            success = lldb_result.returncode == 0

        log_text = ""
        if os.path.exists(log_path):
            with open(log_path, "r", encoding="utf-8") as log_file:
                log_text = log_file.read()
        else:
            success = False
            stderr += "\nmissing lldb gdb-remote log\n"

        output_errors = (
            check_lldb_output(stdout, reg_name, reg_value_hex) if success else []
        )
        log_errors = check_rsp_log(log_text) if log_text else []
        if output_errors or log_errors:
            success = False

        if not success:
            if lldb_result is None:
                print("lldb timed out")
            if output_errors:
                for error in output_errors:
                    print(error)
            if log_errors:
                for error in log_errors:
                    print(error)
            print("--- lldb stdout ---")
            print(stdout)
            print("--- lldb stderr ---")
            print(stderr)
            if log_text:
                print("--- lldb gdb-remote log (tail) ---")
                print("".join(log_text.splitlines()[-40:]))
        else:
            print("--- lldb gdb-remote log (tail) ---")
            print("".join(log_text.splitlines()[-20:]))

    tool_result.terminate(timeout=5)
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
