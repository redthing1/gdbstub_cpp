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


@dataclass(frozen=True)
class E2EInputs:
    reg_name: str
    reg_value_hex: str
    mem_write_hex: str
    mem_write_bin: str
    mem_read_hex: str
    mem_read_bin: str
    mem_read_addr: str
    arch_name: str = "riscv32"


def make_inputs() -> E2EInputs:
    return E2EInputs(
        reg_name="r1",
        reg_value_hex="0x11223344",
        mem_write_hex="M1010,4:01020304",
        mem_write_bin="X1014,4:ABCD",
        mem_read_hex="m1010,4",
        mem_read_bin="x1014,4",
        mem_read_addr="0x1010",
    )


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
    inputs: E2EInputs,
    host: str,
    port: int,
    log_path: str,
) -> list[str]:
    return [
        f"settings set target.default-arch {inputs.arch_name}",
        f"log enable -f {log_path} gdb-remote packets",
        f"gdb-remote {host}:{port}",
        "process plugin packet send qSupported",
        "process plugin packet send QStartNoAckMode",
        "process plugin packet send qXfer:features:read:target.xml:0,200",
        "process plugin packet send qRegisterInfo0",
        "process plugin packet send P1=01020304",
        "process plugin packet send p1",
        "process plugin packet send qHostInfo",
        "process plugin packet send qProcessInfo",
        "process plugin packet send qShlibInfoAddr",
        "process plugin packet send qMemoryRegionInfo:1000",
        "process plugin packet send qXfer:memory-map:read::0,200",
        "process plugin packet send qC",
        "process plugin packet send qThreadStopInfo2",
        "process plugin packet send jThreadsInfo",
        'process plugin packet send jThreadExtendedInfo:{\\"thread\\":2}',
        "process plugin packet send QListThreadsInStopReply",
        "process plugin packet send QThreadSuffixSupported",
        "process plugin packet send p0;thread:2;",
        f"process plugin packet send {inputs.mem_write_hex}",
        f"process plugin packet send {inputs.mem_write_bin}",
        f"process plugin packet send {inputs.mem_read_hex}",
        f"process plugin packet send {inputs.mem_read_bin}",
        "process plugin packet send Z0,1008,4",
        "process plugin packet send z0,1008,4",
        "process plugin packet send c",
        "process plugin packet send D",
    ]


def run_lldb(
    lldb_path: str,
    commands: list[str],
    timeout: float,
) -> subprocess.CompletedProcess[str]:
    args = [lldb_path, "--no-lldbinit", "-b"]
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


def strip_ansi(text: str) -> str:
    ansi_re = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
    return ansi_re.sub("", text)


def parse_packet_responses(stdout: str) -> dict[str, list[str]]:
    responses: dict[str, list[str]] = {}
    last_packet: Optional[str] = None
    for line in stdout.splitlines():
        match_packet = re.match(r"\s*packet:\s*(.+)\s*$", line, re.IGNORECASE)
        if match_packet:
            last_packet = match_packet.group(1).strip()
            continue
        match_response = re.match(r"\s*response:\s*(.*)\s*$", line, re.IGNORECASE)
        if match_response and last_packet is not None:
            responses.setdefault(last_packet, []).append(
                match_response.group(1).strip()
            )
            last_packet = None
    return responses


def require_packet_response(
    packet: str,
    response_pattern: str,
    responses: dict[str, list[str]],
    label: str,
    errors: list[str],
) -> None:
    candidates = responses.get(packet)
    if not candidates:
        errors.append(f"missing output: {label}")
        return
    if not any(
        re.search(response_pattern, candidate, re.IGNORECASE)
        for candidate in candidates
    ):
        errors.append(f"missing output: {label}")


def require_packet_response_prefix(
    prefix: str,
    response_pattern: str,
    responses: dict[str, list[str]],
    label: str,
    errors: list[str],
) -> None:
    candidates: list[str] = []
    for packet, response_list in responses.items():
        if packet.startswith(prefix):
            candidates.extend(response_list)
    if not candidates:
        errors.append(f"missing output: {label}")
        return
    if not any(
        re.search(response_pattern, candidate, re.IGNORECASE)
        for candidate in candidates
    ):
        errors.append(f"missing output: {label}")


def check_lldb_output(stdout: str, inputs: E2EInputs) -> list[str]:
    stdout = strip_ansi(stdout)
    errors: list[str] = []
    responses = parse_packet_responses(stdout)
    require_packet_response(
        "qSupported",
        r".*PacketSize=.*qXfer:features:read\+.*xmlRegisters=",
        responses,
        "qSupported response",
        errors,
    )
    require_packet_response(
        "QStartNoAckMode",
        r"OK",
        responses,
        "QStartNoAckMode response",
        errors,
    )
    require_packet_response(
        "qXfer:features:read:target.xml:0,200",
        r"<target",
        responses,
        "target.xml response",
        errors,
    )
    require_packet_response(
        "qRegisterInfo0",
        r"name:r0;.*bitsize:",
        responses,
        "qRegisterInfo response",
        errors,
    )
    require_packet_response(
        "P1=01020304",
        r"OK",
        responses,
        "register write response",
        errors,
    )
    require_packet_response(
        "p1",
        r"01020304",
        responses,
        "register read response",
        errors,
    )
    require_packet_response(
        "qHostInfo",
        r"hostname:",
        responses,
        "qHostInfo response",
        errors,
    )
    require_packet_response(
        "qProcessInfo",
        r"pid:",
        responses,
        "qProcessInfo response",
        errors,
    )
    require_packet_response(
        "qShlibInfoAddr",
        r"[0-9a-fA-F]+",
        responses,
        "qShlibInfoAddr response",
        errors,
    )
    require_packet_response(
        "qMemoryRegionInfo:1000",
        r"start:.*permissions:",
        responses,
        "qMemoryRegionInfo response",
        errors,
    )
    require_packet_response(
        "qXfer:memory-map:read::0,200",
        r"<memory-map",
        responses,
        "memory-map response",
        errors,
    )
    require_packet_response(
        "qC",
        r"QC",
        responses,
        "qC response",
        errors,
    )
    require_packet_response(
        "qThreadStopInfo2",
        r"thread:2",
        responses,
        "qThreadStopInfo response",
        errors,
    )
    require_packet_response(
        "jThreadsInfo",
        r"\"tid\":1",
        responses,
        "jThreadsInfo response",
        errors,
    )
    require_packet_response_prefix(
        "jThreadExtendedInfo:",
        r"\"thread\":2",
        responses,
        "jThreadExtendedInfo response",
        errors,
    )
    require_packet_response(
        "QListThreadsInStopReply",
        r"OK",
        responses,
        "QListThreadsInStopReply response",
        errors,
    )
    require_packet_response(
        "QThreadSuffixSupported",
        r"OK",
        responses,
        "QThreadSuffixSupported response",
        errors,
    )
    require_packet_response(
        "p0;thread:2;",
        r"[0-9a-fA-F]+",
        responses,
        "thread suffix read response",
        errors,
    )
    require_packet_response(
        inputs.mem_write_hex, r"OK", responses, "memory write hex", errors
    )
    require_packet_response(
        inputs.mem_write_bin, r"OK", responses, "memory write binary", errors
    )
    require_packet_response(
        inputs.mem_read_hex, r"01020304", responses, "memory read hex", errors
    )
    require_packet_response(
        inputs.mem_read_bin, r"ABCD", responses, "memory read binary", errors
    )
    require_packet_response(
        "Z0,1008,4",
        r"OK",
        responses,
        "breakpoint set response",
        errors,
    )
    require_packet_response(
        "z0,1008,4",
        r"OK",
        responses,
        "breakpoint clear response",
        errors,
    )
    require_packet_response(
        "c",
        r"^T",
        responses,
        "continue stop reply",
        errors,
    )
    require_packet_response(
        "D",
        r"OK",
        responses,
        "detach response",
        errors,
    )
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
        lambda payload: payload == "QStartNoAckMode",
        lambda payload: payload == "OK",
    ):
        errors.append("missing QStartNoAckMode response")

    if not response_after(
        events,
        lambda payload: payload.startswith("qXfer:features:read:target.xml"),
        lambda payload: "<target" in payload,
    ):
        errors.append("missing target.xml response")

    if not response_after(
        events,
        lambda payload: payload.startswith("qRegisterInfo"),
        lambda payload: payload.startswith("name:"),
    ):
        errors.append("missing register info response")

    if not response_after(
        events,
        lambda payload: payload.startswith("qHostInfo"),
        lambda payload: "hostname:" in payload,
    ):
        errors.append("missing qHostInfo response")

    if not response_after(
        events,
        lambda payload: payload.startswith("qProcessInfo"),
        lambda payload: "pid:" in payload,
    ):
        errors.append("missing qProcessInfo response")

    if not response_after(
        events,
        lambda payload: payload.startswith("qShlibInfoAddr"),
        lambda payload: payload != "",
    ):
        errors.append("missing qShlibInfoAddr response")

    if not response_after(
        events,
        lambda payload: payload.startswith("qMemoryRegionInfo:"),
        lambda payload: payload.startswith("start:"),
    ):
        errors.append("missing qMemoryRegionInfo response")

    if not response_after(
        events,
        lambda payload: payload.startswith("qXfer:memory-map:read::"),
        lambda payload: "<memory-map" in payload,
    ):
        errors.append("missing memory-map response")

    if not response_after(
        events,
        lambda payload: payload.startswith("qThreadStopInfo"),
        lambda payload: payload.startswith("T"),
    ):
        errors.append("missing qThreadStopInfo response")

    if response_after(
        events,
        lambda payload: payload.startswith("jThreadsInfo"),
        lambda payload: True,
    ):
        if not response_after(
            events,
            lambda payload: payload.startswith("jThreadsInfo"),
            lambda payload: '"tid":1' in unescape_rsp_binary(payload),
        ):
            errors.append("missing tid 1 in jThreadsInfo")
        if not response_after(
            events,
            lambda payload: payload.startswith("jThreadsInfo"),
            lambda payload: '"tid":2' in unescape_rsp_binary(payload),
        ):
            errors.append("missing tid 2 in jThreadsInfo")
        if not response_after(
            events,
            lambda payload: payload.startswith("jThreadsInfo"),
            lambda payload: '"reason":"breakpoint"' in unescape_rsp_binary(payload),
        ):
            errors.append("missing breakpoint reason in jThreadsInfo")

    if response_after(
        events,
        lambda payload: payload.startswith("jThreadExtendedInfo:"),
        lambda payload: True,
    ):
        if not response_after(
            events,
            lambda payload: payload.startswith("jThreadExtendedInfo:"),
            lambda payload: '"thread":2' in unescape_rsp_binary(payload),
        ):
            errors.append("missing thread id in jThreadExtendedInfo")

    if not response_after(
        events,
        lambda payload: payload == "QListThreadsInStopReply",
        lambda payload: payload == "OK",
    ):
        errors.append("missing QListThreadsInStopReply response")

    if not response_after(
        events,
        lambda payload: payload == "QThreadSuffixSupported",
        lambda payload: payload == "OK",
    ):
        errors.append("missing QThreadSuffixSupported response")

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

    if not has_event(
        events,
        "send",
        lambda payload: payload.startswith("M") or payload.startswith("X"),
    ):
        errors.append("missing memory write packet")

    if not response_after(
        events,
        lambda payload: payload.startswith("Z0,1008"),
        lambda payload: payload == "OK",
    ):
        errors.append("missing breakpoint response")

    if not response_after(
        events,
        lambda payload: payload.startswith("z0,1008"),
        lambda payload: payload == "OK",
    ):
        errors.append("missing breakpoint clear response")

    if not response_after(
        events,
        lambda payload: payload == "c" or payload.startswith("vCont;c"),
        lambda payload: payload.startswith("T"),
    ):
        errors.append("missing stop reply after continue")

    if not response_after(
        events,
        lambda payload: payload == "D",
        lambda payload: payload == "OK",
    ):
        errors.append("missing detach response")

    if not has_event(
        events,
        "read",
        lambda payload: payload.startswith("T") and "threads:" in payload,
    ):
        errors.append("missing threads list in stop reply")

    return errors


def build_d_target(dub_path: str, project_dir: str) -> tuple[bool, str]:
    result = subprocess.run(
        [dub_path, "build", "--root", project_dir],
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        return False, result.stdout + result.stderr
    return True, result.stdout


def resolve_d_binary(project_dir: str) -> Optional[str]:
    base = os.path.join(project_dir, "gdbstub_cpp_e2e")
    candidates = [base]
    if os.name == "nt":
        candidates.insert(0, base + ".exe")
    for candidate in candidates:
        if os.path.exists(candidate):
            return candidate
    for root, _, files in os.walk(project_dir):
        for name in files:
            if name == "gdbstub_cpp_e2e" or name == "gdbstub_cpp_e2e.exe":
                return os.path.join(root, name)
    return None


def run_mode(
    mode: str,
    target_path: str,
    lldb_path: str,
    host: str,
    timeout: float,
    inputs: E2EInputs,
) -> tuple[bool, str, str, str, list[str], list[str]]:
    port = next_available_port(host)
    tool_args = [
        target_path,
        "--listen",
        f"{host}:{port}",
        "--mode",
        mode,
    ]

    tool_result = start_process(tool_args)
    ready_line = wait_for_output_line(
        tool_result, lambda line: "waiting for debugger" in line, timeout=5.0
    )
    if ready_line is None:
        tool_output = tool_result.drain_output()
        tool_result.terminate(timeout=5)
        return (
            False,
            "",
            f"target output:\\n{tool_output}",
            "",
            [f"{mode}: target did not start"],
            [],
        )

    with tempfile.TemporaryDirectory() as temp_dir:
        log_path = os.path.join(temp_dir, f"lldb-gdb-remote-dlang-{mode}.log")
        commands = build_lldb_commands(inputs, host, port, log_path)

        mode_timeout = timeout * 1.5 if mode == "async" else timeout
        try:
            lldb_result = run_lldb(lldb_path, commands, mode_timeout)
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

        output_errors = check_lldb_output(stdout, inputs) if success else []
        log_errors = check_rsp_log(log_text) if log_text else []
        if output_errors or log_errors:
            success = False

    tool_result.terminate(timeout=5)
    return success, stdout, stderr, log_text, output_errors, log_errors


def report_failure(
    mode: str,
    stdout: str,
    stderr: str,
    log_text: str,
    output_errors: list[str],
    log_errors: list[str],
) -> None:
    print(f"--- mode {mode} failed ---")
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


def report_success(mode: str, log_text: str) -> None:
    print(f"--- mode {mode} lldb gdb-remote log (tail) ---")
    print("".join(log_text.splitlines()[-20:]))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="LLDB end-to-end test for gdbstub_cpp D bindings"
    )
    parser.add_argument("--lldb", required=True, help="Path to lldb executable")
    parser.add_argument("--dub", default="dub", help="Path to dub executable")
    parser.add_argument(
        "--project",
        default=os.path.join("bindings", "dlang", "e2e"),
        help="Path to the D e2e project",
    )
    parser.add_argument(
        "--target",
        default="",
        help="Path to the D e2e binary (skips build if provided)",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--timeout", type=float, default=25.0)
    parser.add_argument(
        "--mode",
        choices=["blocking", "polling", "async", "all"],
        default="all",
        help="Execution mode to test (default: all).",
    )
    args = parser.parse_args()

    project_dir = os.path.abspath(args.project)

    if args.target:
        target_path = os.path.abspath(args.target)
        if not os.path.exists(target_path):
            print(f"target not found: {target_path}")
            return 1
    else:
        ok, build_output = build_d_target(args.dub, project_dir)
        if not ok:
            print("dub build failed:")
            print(build_output)
            return 1
        target_path = resolve_d_binary(project_dir)
        if target_path is None:
            print("failed to locate built D e2e binary")
            return 1

    inputs = make_inputs()

    modes = ["blocking", "polling", "async"] if args.mode == "all" else [args.mode]
    overall_success = True

    for mode in modes:
        (
            success,
            stdout,
            stderr,
            log_text,
            output_errors,
            log_errors,
        ) = run_mode(
            mode,
            target_path,
            args.lldb,
            args.host,
            args.timeout,
            inputs,
        )

        if not success:
            overall_success = False
            report_failure(mode, stdout, stderr, log_text, output_errors, log_errors)
        else:
            report_success(mode, log_text)

    return 0 if overall_success else 1


if __name__ == "__main__":
    sys.exit(main())
