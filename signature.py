# -*- coding: utf-8 -*-
#! /usr/bin/env python3
from scapy.all import Ether, IP, ICMP
from copy import deepcopy
from typing import Tuple, Optional, List


def switch_directions(signatur: 'Signature') -> Tuple['Signature', 'Signature']:
    """
    Switches the source and destination directions of a given signature.

    Parameters
    ----------
    signatur : Signature
        The signature to switch directions for.

    Returns
    -------
    Tuple[Signature, Signature]
        A tuple containing the original signature with its direction set to '->'
        and the switched signature with its source and destination swapped.
    """
    srcdst = deepcopy(signatur)
    srcdst.dir = '->'
    dstsrc = deepcopy(signatur)
    dstsrc.dir = '->'
    dstsrc.src_ip = dstsrc.dst_ip
    dstsrc.src_port = dstsrc.dst_port
    dstsrc.dst_ip = srcdst.src_ip
    dstsrc.dst_port = srcdst.src_port

    return srcdst, dstsrc


def not_eq(other_: str, self_: str, normal: bool = True) -> bool:
    """
    Checks inequality between two values with special handling for 'any', '!', and ranges.

    Parameters
    ----------
    other_ : str
        The value to compare against.
    self_ : str
        The value to be compared.
    normal : bool, optional
        Whether to perform a normal comparison (default is True).

    Returns
    -------
    bool
        True if the values are not equal based on the rules, False otherwise.
    """
    if normal:
        if other_ == 'IP' and self_ in ['TCP', 'UDP']:
            return False
        else:
            return self_ == other_[1:] if other_[0] == '!' else self_ != other_
    else:
        if self_ == 'any':
            return False
        split = other_.split('!')
        if '-' in other_:
            split_split = split[-1].split('-')
            min_ = split_split[0][1:]
            max_ = split_split[1][:-1]
        else:
            min_ = split[-1]
            max_ = split[-1]

        other_ = range(int(min_), int(max_)+1)
        try:
            self_ = int(self_)
        except ValueError:
            print(f"no meaning full compare/TODO: {self_}")
            return True
        else:
            return (len(split) == 1 and self_ not in other_) or\
                   (len(split) == 2 and self_ in other_)


# Snort3 rule actions that may begin a rule line.
SNORT3_ACTIONS = {'alert', 'drop', 'reject', 'pass', 'log', 'sdrop',
                  'block', 'rewrite', 'react'}
# Layer-3/4 protocols the matcher understands directly.
L3L4_PROTOS = {'tcp', 'udp', 'icmp', 'ip'}


def _to_int(val: str) -> Optional[int]:
    """Best-effort int parse; returns None for ranges/operators we don't model."""
    try:
        return int(str(val).strip())
    except (ValueError, TypeError):
        return None


def _split_options(opt_text: str) -> List[str]:
    """Split a Snort3 option block on ';', ignoring ';' inside quoted strings."""
    opts, buf, in_q = [], '', False
    for ch in opt_text:
        if ch == '"':
            in_q = not in_q
            buf += ch
        elif ch == ';' and not in_q:
            if buf.strip():
                opts.append(buf.strip())
            buf = ''
        else:
            buf += ch
    if buf.strip():
        opts.append(buf.strip())
    return opts


def _parse_detection_filter(val: str) -> Optional[dict]:
    """Parse 'track by_src, count 30, seconds 60' into a dict."""
    d = {}
    for part in val.split(','):
        toks = part.split()
        if len(toks) == 2:
            k, v = toks[0].lower(), toks[1]
            if k == 'track':
                d['track'] = v
            elif k == 'count':
                d['count'] = _to_int(v)
            elif k == 'seconds':
                d['seconds'] = _to_int(v)
    return d or None


class Signature(object):
    """
    A network packet signature.

    A Signature can be built from three sources:
      * a live Scapy ``Ether`` packet (used by the analyzer to describe traffic),
      * a simple positional rule string  ``PROTO IP:PORT -> IP:PORT *PAYLOAD``
        (the format used by ``default.rules`` / ``eval.rules``), or
      * a full Snort3 rule string
        ``alert tcp $HOME_NET 80 -> $EXTERNAL_NET any ( msg:"..."; content:"..."; sid:1; )``.

    For Snort3 rules the parser also populates the richer attributes consumed by
    the staged matcher in ``rules.match_rule`` (protocol, content, flow, pcre,
    flags, ICMP fields, service, sid, detection_filter, ...). Simple rules and
    packet-derived signatures leave those attributes at safe defaults so the same
    code paths never raise ``AttributeError``.
    """

    def __init__(self, obj):
        super(Signature, self).__init__()

        # ── Rich attributes consumed by rules.match_rule (safe defaults) ──────
        self.is_snort3 = False
        self.sid = ''
        self.msg = ''
        self.rev = ''
        self.classtype = ''
        self.protocol = ''          # lowercase ('tcp'/'udp'/'icmp'/'ip')
        self.service = ''
        self.flow = ''
        self.content = ''           # primary content string (matcher uses one)
        self.contents = []          # every content seen (informational)
        self.nocase = False
        self.depth = 0
        self.offset = 0
        self.fast_pattern = False
        self.pcre = ''
        self.http_uri = False
        self.http_header = ''
        self.flags = ''
        self.itype = None
        self.icode = None
        self.icmp_id = None
        self.byte_test = ''
        self.detection_filter = None

        if isinstance(obj, Ether):
            direction = '->'
            s_id = '-1'
            if IP in obj:
                proto = obj[2].name
                src_ip = str(obj[1].src)
                dst_ip = str(obj[1].dst)
                payload = '*'
                try:
                    src_port = str(obj[1].sport)
                    dst_port = str(obj[1].dport)
                except AttributeError:
                    if ICMP in obj:
                        src_port = 'any'
                        dst_port = 'any'
                    else:
                        raise ValueError()
                except IndexError:
                    raise ValueError()
            else:
                raise ValueError()
            self._assign(s_id, proto, src_ip, src_port, direction, dst_ip, dst_port, payload)

        elif isinstance(obj, str):
            text = obj.strip()
            first = text.split(' ', 1)[0].lower() if text else ''
            if first in SNORT3_ACTIONS and '(' in text and ')' in text:
                self._parse_snort3(text)
            else:
                self._parse_simple(text)
        else:
            raise ValueError(obj, 'cant be initialized')

    # ── Construction helpers ─────────────────────────────────────────────────
    def _assign(self, s_id, proto, src_ip, src_port, direction, dst_ip, dst_port, payload):
        self.s_id = s_id
        self.proto = proto
        self.src_ip = src_ip
        self.src_port = src_port
        self.dir = direction
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.payload = payload
        if not self.protocol:
            self.protocol = str(proto).lower()
        if not self.sid:
            self.sid = s_id

    def _parse_simple(self, text):
        """Parse the simple positional rule format used by default/eval.rules."""
        string = text.split(' ')
        if len(string) == 5:
            src_split = string[1].split(':')
            dst_split = string[3].split(':')
            self._assign('', string[0], src_split[0], src_split[1],
                         string[2], dst_split[0], dst_split[1], string[4])
        elif len(string) == 6:
            src_split = string[2].split(':')
            dst_split = string[4].split(':')
            self._assign(string[0].split(':')[0], string[1], src_split[0], src_split[1],
                         string[3], dst_split[0], dst_split[1], string[5])
        else:
            raise ValueError(f'Unrecognised rule format: {text!r}')

    def _set_proto(self, tok, service_form=False):
        tok = tok.lower()
        if tok in L3L4_PROTOS:
            self.protocol = tok
            self.proto = tok.upper()
        else:
            # A service keyword (http, ssl, dns, smtp, ...) instead of an L3/L4
            # protocol: match on the IP layer only and remember the service.
            self.service = self.service or tok
            self.protocol = 'ip'
            self.proto = 'IP'

    def _parse_snort3(self, text):
        """Parse a full Snort3 rule into header fields and options."""
        self.is_snort3 = True
        self.payload = '*'
        open_idx = text.index('(')
        close_idx = text.rindex(')')
        header = text[:open_idx].strip()
        opt_text = text[open_idx + 1:close_idx]

        body = header.split()[1:]          # drop the action keyword
        # Defaults for header-less / service-form rules.
        self.s_id = ''
        self.src_ip = self.src_port = 'any'
        self.dst_ip = self.dst_port = 'any'
        self.dir = '->'
        self.proto = 'IP'
        self.protocol = 'ip'

        if len(body) >= 6:
            self.src_ip, self.src_port = body[1], body[2]
            self.dir = body[3]
            self.dst_ip, self.dst_port = body[4], body[5]
            self._set_proto(body[0])
        elif len(body) >= 1:
            self._set_proto(body[0], service_form=True)
        else:
            raise ValueError(f'Snort3 rule has no protocol: {text!r}')

        for opt in _split_options(opt_text):
            self._apply_option(opt)

    def _apply_option(self, opt):
        if ':' in opt:
            key, val = opt.split(':', 1)
            key, val = key.strip().lower(), val.strip()
        else:
            key, val = opt.strip().lower(), ''

        if key == 'msg':
            self.msg = val.strip().strip('"')
        elif key == 'sid':
            self.sid = self.s_id = val.strip()
        elif key == 'rev':
            self.rev = val
        elif key == 'classtype':
            self.classtype = val
        elif key == 'service':
            self.service = val.split(',')[0].strip()
        elif key == 'flow':
            self.flow = val.strip().strip('"')
        elif key == 'flags':
            self.flags = val.split(',')[0].strip().strip('"')
        elif key == 'content':
            self._parse_content(val)
        elif key == 'pcre':
            if not self.pcre:
                self.pcre = f'pcre:{val.strip()}'      # val keeps its quotes
        elif key == 'itype':
            self.itype = _to_int(val)
        elif key == 'icode':
            self.icode = _to_int(val)
        elif key in ('icmp_id', 'id'):
            self.icmp_id = _to_int(val)
        elif key == 'byte_test':
            self.byte_test = val
        elif key == 'detection_filter':
            self.detection_filter = _parse_detection_filter(val)
        elif key == 'depth':
            iv = _to_int(val)
            if iv is not None:
                self.depth = iv
        elif key == 'offset':
            iv = _to_int(val)
            if iv is not None:
                self.offset = iv
        elif key == 'nocase':
            self.nocase = True
        elif key == 'fast_pattern':
            self.fast_pattern = True
        # All other options (buffers, metadata, references, ...) are ignored.

    def _parse_content(self, val):
        """Parse a content option: a quoted string plus comma-separated modifiers."""
        val = val.strip()
        negated = False
        if val.startswith('!'):
            negated = True
            val = val[1:].strip()
        if not val.startswith('"'):
            return
        end = val.find('"', 1)
        if end < 0:
            return
        string = val[1:end]
        mods = val[end + 1:].lstrip(', ').split(',')
        self.contents.append(string)

        # The first positive content becomes the primary matched pattern.
        if not negated and not self.content:
            self.content = string
            for m in mods:
                m = m.strip()
                if m == 'nocase':
                    self.nocase = True
                elif m == 'fast_pattern':
                    self.fast_pattern = True
                elif m.startswith('depth'):
                    iv = _to_int(m.split()[-1]) if len(m.split()) > 1 else None
                    if iv is not None:
                        self.depth = iv
                elif m.startswith('offset'):
                    iv = _to_int(m.split()[-1]) if len(m.split()) > 1 else None
                    if iv is not None:
                        self.offset = iv

    # ── Representation / comparison (used by the simple analyzer path) ────────
    def __str__(self):
        return f"{self.proto} {self.src_ip}:{self.src_port} {self.dir} {self.dst_ip}:{self.dst_port} {self.payload}"

    def __repr__(self):
        return f"ruleID {self.s_id}"

    def __eq__(self, other):
        """
        not commutative
        self always without !/any/<>/portRange
        """
        if isinstance(self, other.__class__):
            if other.dir == '<>':
                dir_a, dir_b = switch_directions(other)
                return self.__eq__(dir_a) or self.__eq__(dir_b)
            if other.proto != 'any':
                if not_eq(other.proto, self.proto):
                    return False
            if other.src_ip != 'any':
                if not_eq(other.src_ip, self.src_ip):
                    return False
            if other.src_port != 'any':
                if not_eq(other.src_port, self.src_port, 0):
                    return False
            if other.dst_ip != 'any':
                if not_eq(other.dst_ip, self.dst_ip):
                    return False
            if other.dst_port != 'any':
                if not_eq(other.dst_port, self.dst_port, 0):
                    return False
            if other.payload != 'any':
                if self.payload != other.payload:
                    return False
            return True
        else:
            return False
