"""Text heuristics for tool poisoning. Pure functions, property-tested.

These are signals, not verdicts: findings built on them carry medium confidence and the
Claude Code skill adds a semantic review on top.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit

# --- invisible and control characters ---------------------------------------------------

BIDI_CONTROLS = frozenset(
    "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\u200e\u200f\u061c"
)
ZERO_WIDTH = frozenset("\u200b\u200c\u200d\u2060\ufeff\u180e")
TAG_RANGE = range(0xE0000, 0xE0080)
VARIATION_SELECTORS_SUPP = range(0xE0100, 0xE01F0)


@dataclass(frozen=True)
class HiddenChar:
    index: int
    codepoint: str
    kind: str  # bidi | zero-width | tag | variation-selector | format | private-use | control


def _kind(ch: str) -> str | None:
    cp = ord(ch)
    if ch in BIDI_CONTROLS:
        return "bidi"
    if ch in ZERO_WIDTH:
        return "zero-width"
    if cp in TAG_RANGE:
        return "tag"
    if cp in VARIATION_SELECTORS_SUPP:
        return "variation-selector"
    cat = unicodedata.category(ch)
    if cat == "Cf":
        return "format"
    if cat == "Co":
        return "private-use"
    if cat == "Cc" and ch not in "\n\r\t":
        return "control"
    return None


def _is_emoji_zwj(text: str, i: int) -> bool:
    """A ZWJ between two symbols is a legitimate emoji sequence."""
    if text[i] != "\u200d" or i == 0 or i == len(text) - 1:
        return False

    def symbol(ch: str) -> bool:
        return unicodedata.category(ch) == "So" or 0x1F000 <= ord(ch) <= 0x1FAFF

    prev = text[i - 1] if text[i - 1] not in "️" else text[i - 2] if i > 1 else ""
    return bool(prev) and symbol(prev) and symbol(text[i + 1])


def hidden_chars(text: str) -> list[HiddenChar]:
    out = []
    for i, ch in enumerate(text):
        kind = _kind(ch)
        if kind is None or _is_emoji_zwj(text, i):
            continue
        out.append(HiddenChar(i, f"U+{ord(ch):04X}", kind))
    return out


def decode_tags(text: str) -> str:
    """Unicode tag characters mirror ASCII; attackers use them to hide whole sentences."""
    return "".join(chr(ord(c) - 0xE0000) for c in text if ord(c) in TAG_RANGE)


def visible(text: str) -> str:
    """Render hidden characters as <U+XXXX> so evidence shows what a human cannot see."""
    out = []
    for i, ch in enumerate(text):
        if _kind(ch) is not None and not _is_emoji_zwj(text, i):
            out.append(f"<U+{ord(ch):04X}>")
        else:
            out.append(ch)
    return "".join(out)


# --- instruction-like phrases -----------------------------------------------------------

_SILENT_ACTIONS = (
    r"(?:send|upload|forward|transmit|post|share|exfiltrat|cop(?:y|ie)|attach|include|"
    r"append|read|access|fetch|collect|call|invoke|run|execut|install|modify|chang|delet|remov|"
    r"overwrit|grant)"
)
_INSTRUCTIONS: tuple[tuple[str, str], ...] = (
    (
        "override",
        r"\b(ignore|disregard|forget|override)\b.{0,30}\b(previous|prior|above|earlier|all|any|other|system)\b.{0,20}\b(instructions?|prompts?|rules?|directions?)",
    ),
    (
        "secrecy",
        r"\b(do not|don't|never)\b.{0,20}\b(tell|inform|mention|reveal|show|notify|alert)\b.{0,20}\b(the )?(user|human|operator)",
    ),
    (
        "secrecy",
        # "silently" alone is common API prose ("unknown IDs are silently ignored"): it only
        # counts next to an action that moves or touches data.
        r"\b(secretly|covertly|without (the )?(user|human)('s)? (knowing|knowledge|consent|noticing))"
        r"|\bsilently\s+(?:\w+\s+){0,2}?"
        + _SILENT_ACTIONS
        + r"|\b"
        + _SILENT_ACTIONS
        + r"\w*\s+(?:\S+\s+){0,4}?silently\b",
    ),
    (
        "ordering",
        r"\b(before|after|instead of)\b.{0,15}\b(using|calling|invoking|running)\b.{0,20}\b(this|any|every|other|the)\b.{0,15}\btools?\b",
    ),
    (
        "ordering",
        r"\b(always|must|first)\b.{0,20}\b(call|use|invoke|run)\b.{0,20}\b(this tool|the \w+ tool)\b",
    ),
    (
        "imperative",
        r"\byou (must|should|need to|have to|are required to)\b.{0,40}\b(read|send|include|pass|forward|upload|copy|attach)\b",
    ),
    (
        "exfiltration",
        r"\b(send|post|upload|forward|exfiltrate|leak|transmit)\b.{0,40}\b(to|via)\b.{0,40}\b(https?://|webhook|endpoint|server|email|address)",
    ),
    (
        "exfiltration",
        r"\b(read|cat|open|load)\b.{0,30}(~/|\.ssh|id_rsa|\.env\b|credentials|private key|api[_ ]?key|secrets?)",
    ),
    ("exfiltration", r"\bpass\b.{0,30}\b(its|the|their) (content|contents|value)\b.{0,30}\bas\b"),
    (
        "role",
        r"(<\s*/?\s*(important|system|instructions?|admin|secret)\s*>|\[/?INST\]|<\|im_start\|>|###\s*system)",
    ),
    ("role", r"\b(system prompt|developer mode|jailbreak|act as (an? )?(admin|root|system))\b"),
    # French: the same families, so a translated injection is not a blind spot.
    (
        "override",
        r"\b(ignore[rsz]?|oublie[rsz]?|ne tiens pas compte|ne tenez pas compte)\b.{0,30}"
        r"\b(instructions?|consignes?|r[èe]gles?|directives?)\b.{0,20}"
        r"\b(pr[ée]c[ée]dentes?|ant[ée]rieures?|ci-dessus|syst[èe]me)",
    ),
    (
        "secrecy",
        r"\bne\b.{0,15}\b(dis|dites|dire|mentionne[rz]?|r[ée]v[èe]le[rz]?|signale[rz]?|"
        r"informe[rz]?|pr[ée]viens|pr[ée]venez|pr[ée]venir|montre[rz]?)\b.{0,20}"
        r"\b(rien|pas|jamais)\b.{0,20}\b(l'|à l'|aux? )?(utilisateur|utilisatrice|usager)",
    ),
    (
        "secrecy",
        r"\b(secr[èe]tement|en secret|à l'insu de l'utilisat\w*|sans que l'utilisat\w* (ne )?"
        r"(le )?(sache|remarque|voie)|sans (le )?(dire|signaler|pr[ée]venir|informer) "
        r"(à )?l'utilisat\w*)",
    ),
    (
        "ordering",
        r"\b(avant|apr[èe]s|au lieu)\b.{0,15}\b(d'utiliser|d'appeler|d'invoquer|de lancer|"
        r"tout autre|toute autre|chaque)\b.{0,25}\boutils?\b",
    ),
    (
        "imperative",
        r"\b(tu dois|vous devez|il faut|tu es oblig[ée]|vous [êe]tes oblig[ée]s?)\b.{0,40}"
        r"\b(lire|envoyer|inclure|transmettre|t[ée]l[ée]verser|copier|joindre|transf[ée]rer)\b",
    ),
    (
        "exfiltration",
        r"\b(envoie[rsz]?|envoyez|transmet[st]?|transmettez|transmettre|t[ée]l[ée]verse[rz]?|"
        r"transf[èée]re[rz]?|poste[rz]?)\b.{0,40}\b(à|vers|via|sur)\b.{0,40}"
        r"(https?://|webhook|serveur|e-?mail|adresse|point de terminaison)",
    ),
    (
        "exfiltration",
        r"\b(lis|lisez|lire|ouvre[rz]?|charge[rz]?|r[ée]cup[èe]re[rz]?)\b.{0,30}"
        r"(~/|\.ssh|id_rsa|\.env\b|identifiants|cl[ée] priv[ée]e|cl[ée] d'api|cl[ée] api|"
        r"mots? de passe|secrets?)",
    ),
    ("role", r"\b(prompt syst[èe]me|invite syst[èe]me|mode d[ée]veloppeur)\b"),
)
_INSTRUCTION_RES = tuple((label, re.compile(p, re.I | re.S)) for label, p in _INSTRUCTIONS)


def instruction_phrases(text: str) -> list[tuple[str, str]]:
    """(label, matched text) for every instruction-like phrase."""
    out = []
    for label, pattern in _INSTRUCTION_RES:
        for m in pattern.finditer(text):
            out.append((label, " ".join(m.group(0).split())[:120]))
    return out


# --- encoded blobs -----------------------------------------------------------------------

_B64 = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{40,}={0,2}(?![A-Za-z0-9+/=_-])")
_HEX = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}){32,}(?![0-9a-fA-F])")
_PCT = re.compile(r"(?:%[0-9a-fA-F]{2}){10,}")
_DATA_URI = re.compile(r"data:[\w/+.-]+;base64,[A-Za-z0-9+/=]{16,}", re.I)


@dataclass(frozen=True)
class Blob:
    kind: str
    snippet: str
    decoded: str | None


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    return sum(1 for c in s if c.isprintable() or c in "\n\t") / len(s)


def _try_b64(s: str) -> str | None:
    padded = s + "=" * (-len(s) % 4)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            raw = decoder(padded)
        except (binascii.Error, ValueError):
            continue
        text = raw.decode("utf-8", errors="replace")
        if _printable_ratio(text) > 0.9:
            return text
    return None


def encoded_blobs(text: str) -> list[Blob]:
    out: list[Blob] = []
    for m in _DATA_URI.finditer(text):
        out.append(Blob("data-uri", m.group(0)[:60], None))
    for m in _B64.finditer(text):
        s = m.group(0)
        if s.isalpha() and (s.islower() or s.isupper()):
            continue  # a long word, not base64
        if re.fullmatch(r"[0-9a-fA-F]+", s):
            continue  # handled as hex
        decoded = _try_b64(s)
        if decoded is not None or _entropy_like(s):
            out.append(Blob("base64", s[:60], decoded[:200] if decoded else None))
    for m in _HEX.finditer(text):
        s = m.group(0)
        try:
            decoded = bytes.fromhex(s).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            decoded = None
        out.append(
            Blob(
                "hex",
                s[:60],
                decoded[:200] if decoded and _printable_ratio(decoded) > 0.9 else None,
            )
        )
    for m in _PCT.finditer(text):
        out.append(Blob("percent", m.group(0)[:60], unquote(m.group(0))[:200]))
    return out


def _entropy_like(s: str) -> bool:
    classes = sum(
        (any(c.islower() for c in s), any(c.isupper() for c in s), any(c.isdigit() for c in s))
    )
    return classes == 3 and len(set(s)) > 20


# --- sensitive paths and URLs ------------------------------------------------------------

_SECRET_PATHS = re.compile(
    r"(~/\.ssh\b|\bid_(rsa|ed25519|ecdsa)\b|\.aws/credentials|\.kube/config|\.docker/config\.json|"
    r"\.npmrc\b|\.pypirc\b|\.netrc\b|\.git-credentials|/etc/(passwd|shadow)\b|\.env\b|"
    r"\.gnupg\b|keychain|claude_desktop_config\.json|\.cursor/mcp\.json|\bmcp\.json\b|"
    r"\.bash_history|\.zsh_history|wallet\.dat)",
    re.I,
)
_URL = re.compile(r"https?://[^\s\"'<>)\]]+", re.I)
_SUSPICIOUS_HOSTS = (
    "ngrok",
    "ngrok-free.app",
    "webhook.site",
    "requestbin",
    "pipedream.net",
    "pastebin.com",
    "burpcollaborator",
    "oast.",
    "interact.sh",
    "trycloudflare.com",
    "discord.com/api/webhooks",
    "hooks.slack.com",
)


def secret_paths(text: str) -> list[str]:
    return sorted({m.group(0) for m in _SECRET_PATHS.finditer(text)})


def suspicious_urls(text: str) -> list[str]:
    out = []
    for m in _URL.finditer(text):
        url = m.group(0).rstrip(".,;")
        host = (urlsplit(url).hostname or "").lower()
        if any(h in url.lower() for h in _SUSPICIOUS_HOSTS) or _is_ip(host):
            out.append(url)
    return out


def _is_ip(host: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


# --- confusable names --------------------------------------------------------------------

_CONFUSABLES = str.maketrans(
    {
        "а": "a",
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "у": "y",
        "х": "x",
        "і": "i",
        "ј": "j",
        "ѕ": "s",
        "ԁ": "d",
        "ɡ": "g",
        "һ": "h",
        "ӏ": "l",
        "ο": "o",
        "α": "a",
        "ν": "v",
        "τ": "t",
        "ı": "i",
        "0": "o",
        "1": "l",
        "5": "s",
        "-": "_",
        ".": "_",
    }
)


def skeleton(name: str) -> str:
    """Rough confusable skeleton: NFKC, casefold, common homoglyphs mapped to ASCII."""
    return unicodedata.normalize("NFKC", name).casefold().translate(_CONFUSABLES)


def non_ascii(name: str) -> bool:
    return any(ord(c) > 127 for c in name)
