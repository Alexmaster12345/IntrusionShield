from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Rule:
    id: int = 0
    action: str = "alert"
    protocol: str = "any"
    src_ip: str = "any"
    src_port: str = "any"
    dst_ip: str = "any"
    dst_port: str = "any"
    msg: str = ""
    flags: str = ""
    content: str = ""
    nocase: bool = False
    sid: int = 0
    rev: int = 1
    severity: int = 1


def load_rules(path: str) -> List[Rule]:
    rules: List[Rule] = []
    try:
        with open(path) as f:
            lines = f.readlines()
    except FileNotFoundError:
        return rules

    for lineno, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            rules.append(_parse_rule(line, lineno))
        except ValueError as e:
            raise ValueError(f"line {lineno}: {e}") from e

    return rules


def _parse_rule(line: str, lineno: int) -> Rule:
    paren_idx = line.find("(")
    if paren_idx < 0:
        raise ValueError("missing options section")

    header = line[:paren_idx].split()
    if len(header) < 7:
        raise ValueError(f"short header: {line[:paren_idx]!r}")

    r = Rule(
        id=lineno,
        action=header[0],
        protocol=header[1],
        src_ip=header[2],
        src_port=header[3],
        # header[4] is direction "->"
        dst_ip=header[5],
        dst_port=header[6],
    )

    opt_str = line[paren_idx + 1:]
    last_paren = opt_str.rfind(")")
    if last_paren >= 0:
        opt_str = opt_str[:last_paren]

    for opt in _split_options(opt_str):
        kv = opt.split(":", 1)
        key = kv[0].strip()
        val = kv[1].strip().strip('"') if len(kv) == 2 else ""

        if key == "msg":
            r.msg = val
        elif key == "flags":
            r.flags = val
        elif key == "content":
            r.content = val
        elif key == "nocase":
            r.nocase = True
        elif key == "sid":
            r.sid = int(val)
        elif key == "rev":
            r.rev = int(val)
        elif key == "severity":
            r.severity = int(val)

    return r


def _split_options(s: str) -> List[str]:
    opts: List[str] = []
    current: List[str] = []
    in_quote = False

    for ch in s:
        if ch == '"':
            in_quote = not in_quote
            current.append(ch)
        elif ch == ";" and not in_quote:
            opt = "".join(current).strip()
            if opt:
                opts.append(opt)
            current = []
        else:
            current.append(ch)

    if current:
        opt = "".join(current).strip()
        if opt:
            opts.append(opt)

    return opts
