#!/usr/bin/env python3
"""Build a real, signed C2PA Content Credential and put it in a JPEG.

The demo fixtures exist so that what augur reports can be checked against a
script that says exactly what it planted. That only works if the thing planted
is the real article: the previous version of this fixture wrote a JPEG segment
containing the letters "jumb" and "c2pa" and nine hundred zero bytes, which the
tool of the day accepted because it was looking for the letters. It is not a
manifest, and augur now says so — which is the correct answer and a useless demo.

So this builds one properly: JUMBF boxes, a CBOR claim, an actions assertion, a
hard binding over the file's own bytes, and a COSE signature made with a
throwaway certificate generated here by openssl. Everything augur then prints
about the file is true, including the part it verifies for itself.

Requires openssl (any version since 1.0; LibreSSL as shipped with macOS is
fine). The key and certificate are generated per run and thrown away: the
private key never touches the repository, and the certificate is self-signed
because nothing in augur validates a chain and pretending otherwise in a fixture
would teach the wrong thing.

One thing this manifest deliberately does not have: a trusted time stamp. That
needs an RFC 3161 authority, which needs the network, and inventing one would be
forging a countersignature rather than building a fixture. The consequence is
worth knowing — c2patool's current policy refuses a manifest without one, so it
will decline this file while augur reads it. augur reports what a credential
says and verifies the binding; it does not enforce a conformance policy, and
that difference is the reason the two disagree here.
"""

import hashlib
import os
import struct
import subprocess
import tempfile

# ---------------------------------------------------------------------------
# CBOR, definite lengths only. Enough for a claim, an assertion and a COSE
# header, which is all this writes.
# ---------------------------------------------------------------------------


def cbor(value) -> bytes:
    if value is None:
        return b"\xf6"
    if isinstance(value, bool):
        return b"\xf5" if value else b"\xf4"
    if isinstance(value, int):
        return _head(0, value) if value >= 0 else _head(1, -1 - value)
    if isinstance(value, bytes):
        return _head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode()
        return _head(3, len(raw)) + raw
    if isinstance(value, list):
        return _head(4, len(value)) + b"".join(cbor(v) for v in value)
    if isinstance(value, dict):
        out = _head(5, len(value))
        for key, val in value.items():
            out += cbor(key) + cbor(val)
        return out
    raise TypeError(f"cbor: {type(value).__name__}")


def _head(major: int, arg: int) -> bytes:
    if arg < 24:
        return bytes([major << 5 | arg])
    if arg < 1 << 8:
        return bytes([major << 5 | 24, arg])
    if arg < 1 << 16:
        return bytes([major << 5 | 25]) + struct.pack(">H", arg)
    if arg < 1 << 32:
        return bytes([major << 5 | 26]) + struct.pack(">I", arg)
    return bytes([major << 5 | 27]) + struct.pack(">Q", arg)


# ---------------------------------------------------------------------------
# JUMBF: a length, a four-character type, and a payload — where a superbox's
# payload is more boxes and the first of them describes the superbox.
# ---------------------------------------------------------------------------

UUID_STORE = "6332706100110010800000AA00389B71"      # c2pa
UUID_MANIFEST = "63326D6100110010800000AA00389B71"   # c2ma
UUID_ASSERTIONS = "6332617300110010800000AA00389B71"  # c2as
UUID_CLAIM = "6332636C00110010800000AA00389B71"      # c2cl
UUID_SIGNATURE = "6332637300110010800000AA00389B71"  # c2cs
UUID_CBOR = "63626F7200110010800000AA00389B71"       # cbor


def box(kind: str, payload: bytes) -> bytes:
    return struct.pack(">I", len(payload) + 8) + kind.encode() + payload


def superbox(label: str, uuid_hex: str, *children: bytes) -> bytes:
    description = bytes.fromhex(uuid_hex) + b"\x03" + label.encode() + b"\x00"
    return box("jumb", box("jumd", description) + b"".join(children))


def cbor_box(label: str, value) -> bytes:
    return superbox(label, UUID_CBOR, box("cbor", cbor(value)))


# ---------------------------------------------------------------------------
# Signing. openssl holds the key; this only assembles what gets signed and
# converts the signature into the form COSE wants.
# ---------------------------------------------------------------------------


def _openssl(args, stdin=None) -> bytes:
    return subprocess.run(
        ["openssl"] + args, input=stdin, capture_output=True, check=True
    ).stdout


def make_signer(subject: str):
    """Generate a throwaway P-256 key and self-signed certificate.

    Returns (certificate DER, sign(bytes) -> raw 64-byte ECDSA signature).
    """
    tmp = tempfile.mkdtemp(prefix="augur-c2pa-")
    key = os.path.join(tmp, "key.pem")
    cert = os.path.join(tmp, "cert.pem")
    _openssl(["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", key])
    _openssl(["req", "-new", "-x509", "-key", key, "-out", cert, "-days", "3650",
              "-subj", subject])
    der = _openssl(["x509", "-in", cert, "-outform", "DER"])

    def sign(message: bytes) -> bytes:
        # openssl emits ECDSA signatures as DER SEQUENCE { INTEGER r, INTEGER s };
        # COSE wants the two integers raw and fixed-width, so they are unpacked
        # here rather than handed over as they came.
        signature = _openssl(["dgst", "-sha256", "-sign", key], stdin=message)
        return _der_to_raw(signature)

    return der, sign


def _der_to_raw(der: bytes) -> bytes:
    assert der[0] == 0x30, "not a DER SEQUENCE"
    at = 2 if der[1] < 0x80 else 2 + (der[1] & 0x7F)
    out = b""
    for _ in range(2):
        assert der[at] == 0x02, "not a DER INTEGER"
        length = der[at + 1]
        value = der[at + 2:at + 2 + length].lstrip(b"\x00")
        out += value.rjust(32, b"\x00")
        at += 2 + length
    return out


def cose_sign1(claim: bytes, cert_der: bytes, sign) -> bytes:
    """A COSE_Sign1 over the claim, with the certificate in the protected header.

    The payload is detached — the claim lives in its own JUMBF box — so what is
    signed is the Sig_structure with the claim as its payload field, and the
    structure written into the file carries null in its place.
    """
    protected = cbor({1: -7, 33: cert_der})  # ES256, x5chain
    to_be_signed = cbor(["Signature1", protected, b"", claim])
    return b"\x84" + cbor(protected) + cbor({}) + b"\xf6" + cbor(sign(to_be_signed))


# ---------------------------------------------------------------------------
# The manifest store.
# ---------------------------------------------------------------------------

IPTC = "http://cv.iptc.org/newscodes/digitalsourcetype/"


def build_store(*, generator, version, title, fmt, source_type, software_agent,
                exclusion, file_bytes, cert_der, sign) -> bytes:
    """Assemble a one-manifest store whose hard binding covers `file_bytes`.

    `exclusion` is (start, length): the bytes the manifest itself will occupy,
    which is what a data hash leaves out — a manifest cannot hash itself.
    """
    actions = {"actions": [{
        "action": "c2pa.created",
        "softwareAgent": software_agent,
        "digitalSourceType": IPTC + source_type,
    }]}
    hash_assertion = {
        "exclusions": [{"start": exclusion[0], "length": exclusion[1]}],
        "name": "jumbf manifest",
        "alg": "sha256",
        "hash": _hash_excluding(file_bytes, exclusion),
    }

    assertion_boxes = [
        ("c2pa.actions", cbor_box("c2pa.actions", actions)),
        ("c2pa.hash.data", cbor_box("c2pa.hash.data", hash_assertion)),
    ]
    claim = {
        "claim_generator": f"{generator}/{version}",
        "claim_generator_info": [{"name": generator, "version": version}],
        "assertions": [
            {"url": f"self#jumbf=c2pa.assertions/{label}",
             "hash": hashlib.sha256(raw).digest()}
            for label, raw in assertion_boxes
        ],
        "signature": "self#jumbf=c2pa.signature",
        "dc:format": fmt,
        "dc:title": title,
        "instanceID": "xmp:iid:00000000-0000-0000-0000-0000000f1c7e",
        "alg": "sha256",
    }
    claim_bytes = cbor(claim)

    manifest = superbox(
        "urn:uuid:00000000-0000-0000-0000-0000000f1c7e", UUID_MANIFEST,
        superbox("c2pa.assertions", UUID_ASSERTIONS, *[raw for _, raw in assertion_boxes]),
        superbox("c2pa.claim", UUID_CLAIM, box("cbor", claim_bytes)),
        superbox("c2pa.signature", UUID_SIGNATURE,
                 box("cbor", cose_sign1(claim_bytes, cert_der, sign))),
    )
    return superbox("c2pa", UUID_STORE, manifest)


def _hash_excluding(data: bytes, exclusion) -> bytes:
    start, length = exclusion
    digest = hashlib.sha256()
    digest.update(data[:start])
    digest.update(data[start + length:])
    return digest.digest()


# ---------------------------------------------------------------------------
# Putting one in a JPEG.
# ---------------------------------------------------------------------------


def sign_jpeg(jpeg: bytes, *, at: int, generator="Aperture Studio", version="3.2",
              title="holiday-photo.jpg", source_type="trainedAlgorithmicMedia",
              software_agent="Aperture Diffusion 2",
              subject="/CN=Aperture Studio Signing/O=Aperture Studio") -> bytes:
    """Insert a signed Content Credential into a JPEG at byte offset `at`.

    The segment's size and the claim's exclusion range depend on each other —
    CBOR writes a larger number in more bytes — so the two are settled by
    building the store until its length stops moving. Real signing tools do the
    same thing for the same reason.
    """
    cert_der, sign = make_signer(subject)

    size = 0
    for _ in range(8):
        placeholder = jpeg[:at] + b"\x00" * size + jpeg[at:]
        store = build_store(
            generator=generator, version=version, title=title, fmt="image/jpeg",
            source_type=source_type, software_agent=software_agent,
            exclusion=(at, size), file_bytes=placeholder,
            cert_der=cert_der, sign=sign,
        )
        segment = _app11(store)
        if len(segment) == size:
            return jpeg[:at] + segment + jpeg[at:]
        size = len(segment)
    raise RuntimeError("the manifest segment's length never settled")


def _app11(store: bytes) -> bytes:
    """Wrap a manifest store in the JPEG segment that carries it.

    The payload is the JPEG XT framing from ISO 19566-5 — the identifier "JP", a
    box instance number and a packet sequence number — followed by the store. A
    store larger than a segment is split across several and every one of them
    repeats this header; the demo's manifest is two kilobytes and fits in one.
    """
    payload = b"JP" + b"\x02\x11" + struct.pack(">I", 1) + store
    if len(payload) + 2 > 0xFFFF:
        raise RuntimeError("manifest too large for a single segment")
    return b"\xFF\xEB" + struct.pack(">H", len(payload) + 2) + payload


# ---------------------------------------------------------------------------
# Putting one in plain text.
# ---------------------------------------------------------------------------


def _selectors(payload: bytes) -> str:
    """Encode bytes as Unicode variation selectors, one per byte.

    Values under sixteen use U+FE00..U+FE0F and the rest U+E0100..U+E01EF. None
    of them render, all of them survive a copy and a paste, and that is the
    point: this is how a Content Credential rides in text that has no container
    to put one in.
    """
    out = []
    for b in payload:
        out.append(chr(0xFE00 + b) if b < 16 else chr(0xE0100 + b - 16))
    return "".join(out)


def sign_text(text: str, *, generator="Lumen Assistant", version="4",
              title="post.txt", source_type="trainedAlgorithmicMedia",
              software_agent="Lumen Assistant 4",
              subject="/CN=Lumen Signing/O=Lumen") -> str:
    """Append a signed Content Credential to a text document.

    The wrapper is the structure the specification defines for unstructured
    text: a zero-width no-break space, then a magic number, a version and a
    length, then the manifest store — every byte of it encoded as a variation
    selector. It goes at the end so that a reader parsing the visible content
    reaches it last.

    The awkward part, and the reason for the loop: the claim excludes the
    wrapper from its own hash by byte range, so the claim has to state a length
    that depends on the claim. Worse, a signature is a fresh random number every
    time, and a byte under sixteen encodes to three bytes where the rest encode
    to four — so rebuilding to fix the length changes the length. The fix is the
    one a real signer uses: settle on a target, then pad up to it. The padding
    sits after the manifest inside the excluded run, where the reader stops at
    the length the wrapper declares and the hash never sees it.
    """
    cert_der, sign = make_signer(subject)
    body = text.encode()

    target = None
    for _ in range(12):
        store = build_store(
            generator=generator, version=version, title=title, fmt="text/plain",
            source_type=source_type, software_agent=software_agent,
            exclusion=(len(body), target or 0), file_bytes=body + b"\x00" * (target or 0),
            cert_der=cert_der, sign=sign,
        )
        wrapper = _wrapper(store)
        length = len(wrapper.encode())
        if target is None:
            target = length + 8   # room to pad into, whatever the next build costs
            continue
        filler = _filler(target - length)
        if filler is None:
            target = length + 8
            continue
        return text + wrapper + filler
    raise RuntimeError("the wrapper's length never settled")


def _wrapper(store: bytes) -> str:
    return "\ufeff" + _selectors(
        b"C2PATXT\x00" + b"\x01" + struct.pack(">I", len(store)) + store
    )


def _filler(missing: int):
    """Selectors adding up to exactly `missing` bytes, or None if that is not
    possible — one selector costs three bytes or four, so one, two and five are
    the only gaps that cannot be filled exactly."""
    if missing == 0:
        return ""
    for four in range(missing // 4 + 1):
        rest = missing - 4 * four
        if rest % 3 == 0:
            return _selectors(bytes([16] * four + [0] * (rest // 3)))
    return None
