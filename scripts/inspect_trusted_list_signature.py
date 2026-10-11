"""Bounded offline signature mathematics under a supplied pin, never trust admission."""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import re
import sys
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from lxml import etree

DS = "{http://www.w3.org/2000/09/xmldsig#}"
TSL = "{http://uri.etsi.org/02231/v2#}"
XADES = "{http://uri.etsi.org/01903/v1.3.2#}"
C14N = "http://www.w3.org/2001/10/xml-exc-c14n#"
ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
SHA512 = "http://www.w3.org/2001/04/xmlenc#sha512"
RSA512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
PROPERTIES = "http://uri.etsi.org/01903#SignedProperties"
MAX_BYTES = 4 * 1024 * 1024
MAX_NODES = 50000
MAX_DEPTH = 64
MAX_CANONICAL = 8 * 1024 * 1024
MAX_NAMESPACE_BINDINGS = 64
MAX_NAMESPACE_BYTES = 2048
MAX_NAMESPACE_WORK = 16 * 1024 * 1024


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def shape(node, tags: list[str], attributes: set[str]) -> None:
    require(node is not None, "missing structural node")
    require([child.tag for child in node] == tags, "unsupported child structure")
    require(set(node.attrib) == attributes, "unsupported attributes")
    require(not node.text or not node.text.strip(), "unexpected structural text")
    require(all(not child.tail or not child.tail.strip() for child in node), "unexpected structural tail")


def algorithm(node, uri: str) -> None:
    shape(node, [], {"Algorithm"})
    require(node.get("Algorithm") == uri, "unsupported algorithm")


def value(node, maximum: int, *, allow_id: bool = False) -> bytes:
    allowed = {"Id"} if allow_id else set()
    require(node is not None and len(node) == 0 and set(node.attrib) <= allowed, "encoded value structure")
    text = node.text or ""
    require(len(text) <= 4 * maximum, "encoded value bound")
    compact = "".join(text.split())
    decoded = base64.b64decode(compact, validate=True)
    require(0 < len(decoded) <= maximum, "decoded value bound")
    require(base64.b64encode(decoded).decode("ascii") == compact, "noncanonical base64")
    return decoded


class _CanonicalBuffer:
    def __init__(self):
        self.buffer = bytearray()

    def write(self, chunk: bytes) -> int:
        require(len(self.buffer) + len(chunk) <= MAX_CANONICAL, "canonical output bound")
        self.buffer.extend(chunk)
        return len(chunk)


def canonical(node) -> bytes:
    sink = _CanonicalBuffer()
    etree.ElementTree(node).write(sink, method="c14n", exclusive=True, with_comments=False)
    return bytes(sink.buffer)


def without_signature(root):
    result = copy.deepcopy(root)
    signature = result.find(DS + "Signature")
    tail = signature.tail
    previous = signature.getprevious()
    if tail:
        if previous is None:
            result.text = (result.text or "") + tail
        else:
            previous.tail = (previous.tail or "") + tail
    result.remove(signature)
    return result


def parse(wire: bytes):
    require(type(wire) is bytes and 0 < len(wire) <= MAX_BYTES, "XML byte bound")
    wire.decode("utf-8", errors="strict")
    require(b"\x00" not in wire and b"<!DOCTYPE" not in wire, "DTD or non-UTF-8 input")
    parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False, huge_tree=False)
    root = etree.fromstring(wire, parser)
    require(root.getroottree().docinfo.encoding.upper() == "UTF-8", "UTF-8 encoding required")
    require(not root.getroottree().docinfo.doctype, "DTD refused")
    require(root.getprevious() is None and root.getnext() is None, "outside-root node")
    require(root.tag == TSL + "TrustServiceStatusList", "trusted-list root required")
    ids = set()
    stack = [(root, 1)]
    count = 0
    namespace_work = 0
    while stack:
        node, depth = stack.pop()
        count += 1
        require(count <= MAX_NODES and depth <= MAX_DEPTH, "XML structural bound")
        require(type(node.tag) is str, "comments, processing instructions or entities refused")
        namespaces = node.nsmap
        require(len(namespaces) <= MAX_NAMESPACE_BINDINGS, "namespace context bound")
        for prefix, uri in namespaces.items():
            prefix_size, uri_size = len((prefix or "").encode("utf-8")), len(uri.encode("utf-8"))
            require(max(prefix_size, uri_size) <= MAX_NAMESPACE_BYTES, "namespace spelling bound")
            namespace_work += prefix_size + uri_size
            require(namespace_work <= MAX_NAMESPACE_WORK, "namespace work bound")
        for key, item in node.attrib.items():
            if etree.QName(key).localname.lower() == "id":
                require(key == "Id" and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,127}", item), "ID spelling")
                require(item not in ids, "duplicate ID")
                ids.add(item)
        stack.extend((child, depth + 1) for child in node)
    signatures = list(root.iter(DS + "Signature"))
    require(len(signatures) == 1 and signatures[0].getparent() is root, "one direct signature required")
    return root, signatures[0], count


def inspect_xml(wire: bytes, signer_sha256: str) -> dict:
    require(type(signer_sha256) is str and re.fullmatch(r"[0-9a-f]{64}", signer_sha256), "signer pin syntax")
    root, signature, count = parse(wire)
    shape(signature, [DS + name for name in ("SignedInfo", "SignatureValue", "KeyInfo", "Object")], {"Id"})
    info, signature_value, key_info, obj = signature
    shape(info, [DS + name for name in ("CanonicalizationMethod", "SignatureMethod", "Reference", "Reference")], set())
    algorithm(info[0], C14N)
    algorithm(info[1], RSA512)
    document_ref, properties_ref = info[2:]
    for ref, attrs, transforms in (
        (document_ref, {"Id", "URI"}, (ENVELOPED, C14N)),
        (properties_ref, {"Type", "URI"}, (C14N,)),
    ):
        shape(ref, [DS + name for name in ("Transforms", "DigestMethod", "DigestValue")], attrs)
        shape(ref[0], [DS + "Transform"] * len(transforms), set())
        for transform, expected in zip(ref[0], transforms, strict=True):
            algorithm(transform, expected)
        algorithm(ref[1], SHA512)
    require(document_ref.get("URI") == "", "whole-document empty reference required")
    require(properties_ref.get("Type") == PROPERTIES, "SignedProperties reference type")
    shape(obj, [XADES + "QualifyingProperties"], set())
    qualifying = obj[0]
    shape(qualifying, [XADES + "SignedProperties"], {"Target"})
    require(qualifying.get("Target") == "#" + signature.get("Id"), "signature target differs")
    properties = qualifying[0]
    shape(properties, [XADES + "SignedSignatureProperties", XADES + "SignedDataObjectProperties"], {"Id"})
    require(properties_ref.get("URI") == "#" + properties.get("Id"), "properties reference differs")
    signing = properties[0]
    shape(signing, [XADES + "SigningTime", XADES + "SigningCertificateV2"], set())
    shape(signing[1], [XADES + "Cert"], set())
    shape(signing[1][0], [XADES + "CertDigest", XADES + "IssuerSerialV2"], set())
    cert_digest = signing[1][0][0]
    shape(cert_digest, [DS + "DigestMethod", DS + "DigestValue"], set())
    algorithm(cert_digest[0], SHA512)
    shape(properties[1], [XADES + "DataObjectFormat"], set())
    data_format = properties[1][0]
    shape(data_format, [XADES + "MimeType"], {"ObjectReference"})
    require(data_format.get("ObjectReference") == "#" + document_ref.get("Id"), "data object reference differs")
    shape(key_info, [DS + "X509Data"], set())
    shape(key_info[0], [DS + "X509Certificate"], set())
    cert_wire = value(key_info[0][0], 16384)
    require(hashlib.sha256(cert_wire).hexdigest() == signer_sha256, "signer pin differs")
    require(hashlib.sha512(cert_wire).digest() == value(cert_digest[1], 64), "signed certificate digest differs")
    cert = x509.load_der_x509_certificate(cert_wire)
    require(cert.public_bytes(serialization.Encoding.DER) == cert_wire, "canonical certificate DER required")
    key = cert.public_key()
    require(isinstance(key, rsa.RSAPublicKey) and key.key_size in (2048, 3072, 4096), "unsupported signing key")
    key.verify(value(signature_value, 512, allow_id=True), canonical(info), padding.PKCS1v15(), hashes.SHA512())
    references = []
    for ref, node in ((document_ref, without_signature(root)), (properties_ref, properties)):
        canonical_wire = canonical(node)
        digest = hashlib.sha512(canonical_wire).digest()
        require(digest == value(ref[2], 64), "reference digest differs")
        references.append({"uri": ref.get("URI"), "canonical_size": len(canonical_wire), "sha512": digest.hex()})
    return {
        "schema": "etzio.trusted-list-signature.inspection.v1",
        "input_sha256": hashlib.sha256(wire).hexdigest(),
        "input_size": len(wire),
        "node_count": count,
        "signer_sha256": signer_sha256,
        "signer_pin_authority": "caller supplied; independent publication assessment required",
        "signature_under_supplied_pin": "verified",
        "references": references,
        "kernel_authority": False,
        "provider_admitted": False,
        "currentness_established": False,
        "revocation_checked": False,
        "legal_qualification_established": False,
    }


def main(argv: list[str] | None = None) -> int:
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("xml", type=Path)
    cli.add_argument("--signer-sha256", required=True)
    args = cli.parse_args(argv)
    try:
        with args.xml.open("rb") as source:
            wire = source.read(MAX_BYTES + 1)
        report = inspect_xml(wire, args.signer_sha256)
    except (ValueError, TypeError, OSError, etree.LxmlError, InvalidSignature, UnsupportedAlgorithm) as exc:
        print(f"inspection refused: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
