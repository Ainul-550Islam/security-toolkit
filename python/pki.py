#!/usr/bin/env python3
# ============================================================================
#  pki.py — pure-stdlib public-key verification + safe XML for Phase 8.
#  ---------------------------------------------------------------------------
#  Used ONLY for VERIFICATION of standard formats (never for signing):
#    - RSA PKCS#1 v1.5 signature verification exactly per RFC 8017
#      (EMSA-PKCS1-v1_5 encoding + RSAVP1). SHA-256 for JWT RS256 and
#      XMLDSIG SAML assertions. Public-exponent math only — no private key
#      material is ever handled here.
#    - Minimal ASN.1 DER parser for PEM SubjectPublicKeyInfo / PKCS#1
#      / X.509 certificates (structure parsing, not cryptography).
#    - XML parsing hardened against XXE/DTD/billion-laughs (stdlib
#      xml.dom.minidom over expat with a strict pre-scan that rejects any
#      DOCTYPE/ENTITY, plus size/depth bounds). minidom preserves prefixes
#      and xmlns declarations, which canonicalization requires.
#    - Exclusive XML Canonicalization (C14N "exc", the subset required by
#      XMLDSIG SignedInfo verification): namespace declarations are emitted
#      only for namespaces actually used by the subtree, attributes are
#      sorted, comments/PIs dropped.
#  This is a verifying implementation of PUBLISHED standards (RFC 8017,
#  RFC 5280, XML-EXC-C14N, XMLDSIG) on top of stdlib hashlib/hmac — no new
#  algorithm is invented and no secret key is ever operated on.
# ============================================================================

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
import xml.dom.minidom as minidom

import errors

# ---------------------------------------------------------------------------
# constants
# ---------------------------------------------------------------------------
MAX_XML_BYTES = 512 * 1024          # SAML responses larger than this: refuse
MAX_XML_DEPTH = 64
_DIGEST_INFO = {                     # RFC 8017 §9.2 DigestInfo prefixes
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
    "sha1": bytes.fromhex("3021300906052b0e03021a05000414"),
}

_NS_DSIG = "http://www.w3.org/2000/09/xmldsig#"
_NS_XMLNS = "http://www.w3.org/2000/xmlns/"
_ENVELOPED_TRANSFORM = ("http://www.w3.org/2000/09/xmldsig#"
                        "enveloped-signature")
_EXC_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#"


def hmac_compare(a: str, b: str) -> bool:
    return hmac.compare_digest(str(a), str(b))


# ---------------------------------------------------------------------------
# ASN.1 DER — minimal reader (tag/length/value walk)
# ---------------------------------------------------------------------------
class _DER:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def read_tlv(self):
        if self.pos + 2 > len(self.data):
            raise errors.ValidationError("der_short")
        tag = self.data[self.pos]
        self.pos += 1
        length = self.data[self.pos]
        self.pos += 1
        if length & 0x80:
            nbytes = length & 0x7F
            if nbytes == 0 or nbytes > 4 or self.pos + nbytes > len(self.data):
                raise errors.ValidationError("der_length")
            length = int.from_bytes(self.data[self.pos:self.pos + nbytes],
                                    "big")
            self.pos += nbytes
        if self.pos + length > len(self.data):
            raise errors.ValidationError("der_short_value")
        value = self.data[self.pos:self.pos + length]
        self.pos += length
        return tag, value


def _der_children(value: bytes):
    d = _DER(value)
    out = []
    while d.pos < len(d.data):
        tag, v = d.read_tlv()
        out.append((tag, v))
    return out


def _der_int(value: bytes) -> int:
    if not value:
        return 0
    return int.from_bytes(value, "big")


def _der_tlv(tag: int, value: bytes) -> bytes:
    """Re-encode tag + minimal-length + value (DER). Used to hand a full
    TLV to the SPKI parser (which expects the complete value)."""
    length = len(value)
    if length < 0x80:
        return bytes([tag, length]) + value
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(raw)]) + raw + value


def parse_rsa_public_key_der(der: bytes) -> tuple[int, int]:
    """PKCS#1 RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent
    INTEGER } — the payload of `BEGIN RSA PUBLIC KEY` PEM blocks and of
    SubjectPublicKeyInfo for rsaEncryption keys."""
    tag, seq = _DER(der).read_tlv()
    if tag != 0x30:
        raise errors.ValidationError("rsa_key_invalid: not a SEQUENCE")
    parts = _der_children(seq)
    if len(parts) < 2 or parts[0][0] != 0x02 or parts[1][0] != 0x02:
        raise errors.ValidationError("rsa_key_invalid: bad structure")
    n = _der_int(parts[0][1])
    e = _der_int(parts[1][1])
    if n <= 0 or e <= 0 or n.bit_length() < 512:
        raise errors.ValidationError("rsa_key_invalid: weak or empty key")
    return n, e


def parse_spki_der(der: bytes) -> tuple[int, int]:
    """SubjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey BIT
    STRING (PKCS#1 RSAPublicKey) }. Returns (n, e)."""
    tag, seq = _DER(der).read_tlv()
    if tag != 0x30:
        raise errors.ValidationError("spki_invalid: not a SEQUENCE")
    parts = _der_children(seq)
    if len(parts) != 2 or parts[1][0] != 0x03:
        raise errors.ValidationError("spki_invalid: bad structure")
    bit_string = parts[1][1]
    if not bit_string or bit_string[0] != 0x00:
        raise errors.ValidationError("spki_invalid: malformed bit string")
    return parse_rsa_public_key_der(bit_string[1:])


def _der_time(tag: int, value: bytes) -> str:
    text = value.decode("ascii", "replace")
    if tag == 0x17:                       # UTCTime YYMMDDHHMMSSZ
        return ("20" + text[:12] if text[:2] < "50" else "19" + text[:12])
    if tag == 0x18:                       # GeneralizedTime YYYYMMDDHHMMSSZ
        return text[:14]
    raise errors.ValidationError("cert_invalid: bad time")


def parse_x509_cert_pem(pem: str) -> dict:
    """Extract the subject public key + validity window from an X.509
    certificate (PEM). Returns {n, e, nb_str, na_str}. Structural ASN.1
    walking only — no certificate trust validation is implied here (trust
    anchors are the configured providers)."""
    body = _pem_body(pem, "CERTIFICATE")
    tag, cert = _DER(body).read_tlv()
    if tag != 0x30:
        raise errors.ValidationError("cert_invalid: not a SEQUENCE")
    parts = _der_children(cert)
    if len(parts) < 3 or parts[0][0] != 0x30:
        raise errors.ValidationError("cert_invalid: bad structure")
    tbs_parts = _der_children(parts[0][1])
    idx = 1 if (tbs_parts and tbs_parts[0][0] == 0xA0) else 0
    if len(tbs_parts) < idx + 6:
        raise errors.ValidationError("cert_invalid: truncated tbs")
    validity_parts = _der_children(tbs_parts[idx + 3][1])
    if len(validity_parts) < 2:
        raise errors.ValidationError("cert_invalid: bad validity")
    spki = tbs_parts[idx + 5]
    n, e = parse_spki_der(_der_tlv(spki[0], spki[1]))
    return {"n": n, "e": e,
            "nb_str": _der_time(validity_parts[0][0], validity_parts[0][1]),
            "na_str": _der_time(validity_parts[1][0], validity_parts[1][1])}


def _pem_body(pem: str, kind: str) -> bytes:
    text = str(pem or "")
    m = re.search(r"-----BEGIN " + kind + r"-----([A-Za-z0-9+/=\s]+?)"
                  r"-----END " + kind + r"-----", text, re.S)
    if not m:
        raise errors.ValidationError(f"pem_invalid: no {kind} block")
    body = "".join(m.group(1).split())
    try:
        return base64.b64decode(body)
    except binascii.Error:
        raise errors.ValidationError("pem_invalid: bad base64") from None


def load_rsa_public_key(pem: str) -> tuple[int, int]:
    """Load an RSA public key from PEM: SPKI (`BEGIN PUBLIC KEY`),
    PKCS#1 (`BEGIN RSA PUBLIC KEY`) or an X.509 certificate."""
    text = str(pem or "")
    if "BEGIN CERTIFICATE" in text:
        c = parse_x509_cert_pem(text)
        return c["n"], c["e"]
    if "BEGIN RSA PUBLIC KEY" in text:
        return parse_rsa_public_key_der(_pem_body(text, "RSA PUBLIC KEY"))
    if "BEGIN PUBLIC KEY" in text:
        return parse_spki_der(_pem_body(text, "PUBLIC KEY"))
    raise errors.ValidationError("pem_invalid: no supported RSA key block")


# ---------------------------------------------------------------------------
# RSA PKCS#1 v1.5 verification (RFC 8017) — verify path only
# ---------------------------------------------------------------------------
def rsa_verify_pkcs1v15(n: int, e: int, signature: bytes, message: bytes,
                        hash_name: str = "sha256") -> bool:
    """RSASSA-PKCS1-v1_5 VERIFY, exactly per RFC 8017 §8.2.2 with the
    EMSA-PKCS1-v1_5 encoding of §9.2. Verification only — no secret key
    operation ever happens here."""
    if hash_name not in _DIGEST_INFO:
        return False
    try:
        digest = hashlib.new(hash_name, message).digest()
    except Exception:
        return False
    k = (n.bit_length() + 7) // 8
    if len(signature) != k:
        return False
    try:
        s = int.from_bytes(signature, "big")
        if s >= n:
            return False
        em = pow(s, e, n).to_bytes(k, "big")      # RSAVP1 (public op only)
    except Exception:
        return False
    t = _DIGEST_INFO[hash_name] + digest
    tlen = len(t)
    if k < tlen + 11:
        return False
    expected = (b"\x00\x01" + b"\xff" * (k - tlen - 3) + b"\x00" + t)
    return em == expected


# ---------------------------------------------------------------------------
# safe XML: reject DTD/entities (XXE + billion-laughs), bound size/depth
# ---------------------------------------------------------------------------
_XML_FORBIDDEN = re.compile(r"<!\s*(?:DOCTYPE|ENTITY|ELEMENT|ATTLIST|"
                            r"NOTATION)\b", re.I)
_XML_DECL = re.compile(r"<\?xml[^>]*\?>", re.I)


def strip_xml_decl(text: str) -> str:
    return _XML_DECL.sub("", text, count=1)


def _check_depth(node, depth: int) -> None:
    if depth > MAX_XML_DEPTH:
        raise errors.ValidationError("xml_invalid: nesting too deep")
    for child in node.childNodes:
        if child.nodeType == child.ELEMENT_NODE:
            _check_depth(child, depth + 1)


def safe_xml_root(text: str):
    """Parse untrusted XML with all entity machinery disabled (minidom over
    expat; DOCTYPE/ENTITY is rejected up front so internal-entity expansion
    — billion laughs — cannot occur). Raises ValidationError on ANY of:
    oversized input, DTD/ENTITY declarations, malformed syntax, excessive
    depth."""
    raw = str(text or "")
    if len(raw.encode("utf-8", "replace")) > MAX_XML_BYTES:
        raise errors.ValidationError("xml_invalid: oversized")
    if _XML_FORBIDDEN.search(raw):
        raise errors.ValidationError("xml_invalid: DTD/entity declarations "
                                     "are not allowed")
    data = strip_xml_decl(raw)
    try:
        doc = minidom.parseString(data)
    except Exception as e:
        raise errors.ValidationError(
            f"xml_invalid: parse error ({e})") from None
    root = doc.documentElement
    if root is None:
        raise errors.ValidationError("xml_invalid: no root element")
    _check_depth(root, 0)
    return root


def xml_text(node) -> str:
    """Text content of one element (text children concatenated; tags dropped)."""
    if node is None:
        return ""
    parts = []
    for child in node.childNodes:
        if child.nodeType == child.TEXT_NODE or \
                child.nodeType == child.CDATA_SECTION_NODE:
            parts.append(child.data)
    return "".join(parts)


def find_child(node, ns: str, local: str):
    for child in node.childNodes:
        if child.nodeType == child.ELEMENT_NODE and \
                child.namespaceURI == ns and child.localName == local:
            return child
    return None


def find_all(node, ns: str, local: str) -> list:
    out = []

    def walk(el):
        for child in el.childNodes:
            if child.nodeType != child.ELEMENT_NODE:
                continue
            if child.namespaceURI == ns and child.localName == local:
                out.append(child)
            walk(child)

    walk(node)
    return out


# ---------------------------------------------------------------------------
# exclusive XML canonicalization (subset needed for XMLDSIG verification)
# ---------------------------------------------------------------------------
def _escape_text(text: str) -> str:
    return (text.replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace("\r", "&#xD;"))


def _escape_attr(text: str) -> str:
    return (text.replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;")
            .replace("\t", "&#x9;").replace("\n", "&#xA;")
            .replace("\r", "&#xD;"))


def _own_decls(node) -> dict:
    """xmlns declarations declared ON this element (attr.name == 'xmlns'
    or 'xmlns:prefix')."""
    out: dict[str, str] = {}
    if not node.attributes:
        return out
    for i in range(node.attributes.length):
        attr = node.attributes.item(i)
        name = attr.name or ""
        if name == "xmlns":
            out[""] = attr.value
        elif name.startswith("xmlns:"):
            out[name[len("xmlns:"):]] = attr.value
    return out


def _prefix_for(uri: str, scope: dict) -> str | None:
    for prefix, value in scope.items():
        if value == uri:
            return prefix
    return None


def _used_prefixes(node, scope: dict) -> set:
    used: set[str] = set()

    def walk(el):
        if el.namespaceURI:
            prefix = _prefix_for(el.namespaceURI, scope)
            if prefix is not None:
                used.add(prefix)
            elif el.prefix:
                used.add(el.prefix)
        if el.attributes:
            for i in range(el.attributes.length):
                attr = el.attributes.item(i)
                name = attr.name or ""
                if name == "xmlns" or name.startswith("xmlns:"):
                    continue
                if attr.namespaceURI and attr.namespaceURI != _NS_XMLNS:
                    prefix = _prefix_for(attr.namespaceURI, scope)
                    if prefix is not None:
                        used.add(prefix)
                    elif attr.prefix:
                        used.add(attr.prefix)
        for child in el.childNodes:
            if child.nodeType == child.ELEMENT_NODE:
                walk(child)

    walk(node)
    return used


def exc_c14n(node, inherited_ns: dict | None = None) -> str:
    """Exclusive C14N (XML-EXC-C14N) of one element subtree. Namespace
    declarations emitted are the visibly-utilized ones (promoted from
    ancestors per the spec), attributes are sorted by (namespace-URI,
    local-name), comments/PIs are dropped, CR is escaped everywhere. This
    is the canonical form XMLDSIG covers for SignedInfo/Assertion."""
    scope = dict(inherited_ns or {})
    scope.update(_own_decls(node))
    local = node.localName or node.tagName
    out = ["<", local]
    used = _used_prefixes(node, scope)
    for prefix in sorted(used):
        value = scope.get(prefix)
        if value is None:
            continue
        if prefix == "":
            out.append(f' xmlns="{_escape_attr(value)}"')
        else:
            out.append(f' xmlns:{prefix}="{_escape_attr(value)}"')
    attrs = []
    if node.attributes:
        for i in range(node.attributes.length):
            attr = node.attributes.item(i)
            name = attr.name or ""
            if name == "xmlns" or name.startswith("xmlns:"):
                continue
            attrs.append((attr.namespaceURI or "", attr.localName or name,
                          name, attr.value))
    for auri, alocal, aname, avalue in sorted(attrs):
        if auri and auri != _NS_XMLNS:
            prefix = _prefix_for(auri, scope) or ""
            if prefix:
                out.append(f' {prefix}:{alocal}="{_escape_attr(avalue)}"')
            else:
                out.append(f' {aname}="{_escape_attr(avalue)}"')
        else:
            out.append(f' {alocal}="{_escape_attr(avalue)}"')
    out.append(">")
    for child in node.childNodes:
        if child.nodeType == child.ELEMENT_NODE:
            out.append(exc_c14n(child, scope))
        elif child.nodeType in (child.TEXT_NODE, child.CDATA_SECTION_NODE):
            out.append(_escape_text(child.data))
    out.append("</" + local + ">")
    return "".join(out)


# ---------------------------------------------------------------------------
# XMLDSIG verification (enveloped signatures)
# ---------------------------------------------------------------------------
def verify_xmldsig(assertion, n: int, e: int, *, require: bool = True) -> dict:
    """Verify a SAML XMLDSIG enveloped signature over the given assertion
    DOM element. Exactly one direct ds:Signature child; digest over the
    assertion with the Signature removed (enveloped-signature transform);
    signature over the exclusive-C14N canonicalized SignedInfo.
    Returns {verified, digest_algo}; raises ValidationError on malformed
    structures; verified=False for bad signatures/transforms."""
    sig = find_child(assertion, _NS_DSIG, "Signature")
    if sig is None:
        if require:
            raise errors.ValidationError(
                "saml_invalid: signed assertion required")
        return {"verified": False, "reason": "unsigned"}
    signed_info = find_child(sig, _NS_DSIG, "SignedInfo")
    sig_value = find_child(sig, _NS_DSIG, "SignatureValue")
    if signed_info is None or sig_value is None:
        raise errors.ValidationError("saml_invalid: incomplete signature")
    transforms = []
    transforms_el = find_child(signed_info, _NS_DSIG, "Transforms")
    if transforms_el is not None:
        for t in find_all(transforms_el, _NS_DSIG, "Transform"):
            transforms.append(t.getAttribute("Algorithm") or "")
    for algo in transforms:
        if algo == _ENVELOPED_TRANSFORM:
            continue
        if algo and algo.startswith(_EXC_C14N):
            continue
        raise errors.ValidationError(
            "saml_invalid: unsupported signature transform")
    # 1) digest over the enveloped element (assertion minus Signature)
    import copy
    work = copy.deepcopy(assertion)
    work_sig = find_child(work, _NS_DSIG, "Signature")
    if work_sig is not None:
        work.removeChild(work_sig)
    canonical_assertion = exc_c14n(work).encode("utf-8")
    digest_methods = find_all(signed_info, _NS_DSIG, "DigestMethod")
    digest_values = find_all(signed_info, _NS_DSIG, "DigestValue")
    digest_method = digest_methods[0] if digest_methods else None
    digest_value = digest_values[0] if digest_values else None
    if digest_value is None or not digest_value.firstChild:
        raise errors.ValidationError("saml_invalid: digest missing")
    algo = (digest_method.getAttribute("Algorithm")
            if digest_method is not None else "")
    hash_name = "sha256" if algo.endswith("sha256") else (
        "sha1" if algo.endswith("sha1") else
        "sha384" if algo.endswith("sha384") else "sha512")
    got = hashlib.new(hash_name, canonical_assertion).digest()
    want_raw = "".join((digest_value.firstChild.data or "").split())
    want = None
    try:
        want = base64.b64decode(want_raw, validate=True)
    except (binascii.Error, ValueError):
        try:
            want = bytes.fromhex(want_raw)
        except ValueError:
            want = None
    if want is None or not hmac_compare(got.hex(), want.hex()):
        return {"verified": False, "reason": "digest_mismatch"}
    # 2) signature verification over canonicalized SignedInfo
    canonical_si = exc_c14n(signed_info).encode("utf-8")
    sig_methods = find_all(signed_info, _NS_DSIG, "SignatureMethod")
    sig_method = sig_methods[0] if sig_methods else None
    algo = (sig_method.getAttribute("Algorithm")
            if sig_method is not None else "")
    hash_name = "sha256" if algo.endswith("rsa-sha256") else (
        "sha384" if algo.endswith("rsa-sha384") else
        "sha512" if algo.endswith("rsa-sha512") else "sha1")
    try:
        raw_sig = base64.b64decode("".join(
            (sig_value.firstChild.data or "").split()))
    except binascii.Error:
        return {"verified": False, "reason": "bad_signature_encoding"}
    ok = rsa_verify_pkcs1v15(n, e, raw_sig, canonical_si, hash_name)
    if not ok:
        return {"verified": False, "reason": "signature_mismatch"}
    return {"verified": True, "digest_algo": hash_name}
