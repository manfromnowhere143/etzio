"""Owned signed XML controls; no provider contact or third-party execution."""

import base64
import copy
import hashlib
import json
import socket
import subprocess
from datetime import UTC, datetime

import pytest
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from lxml import etree

from scripts import inspect_trusted_list_signature as inspect

D, T, X = inspect.DS, inspect.TSL, inspect.XADES


def add(parent, tag, text=None, **attrs):
    result = etree.SubElement(parent, tag, **attrs)
    result.text = text
    return result


def encoded(wire):
    return base64.b64encode(wire).decode("ascii")


def c14n(node):
    return etree.tostring(node, method="c14n", exclusive=True, with_comments=False)


@pytest.fixture(scope="module")
def owned():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Etzio owned XML fixture")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(7)
        .not_valid_before(datetime(2020, 1, 1, tzinfo=UTC))
        .not_valid_after(datetime(2020, 1, 2, tzinfo=UTC))
        .sign(key, hashes.SHA256())
    ).public_bytes(serialization.Encoding.DER)
    root = etree.Element(T + "TrustServiceStatusList", nsmap={None: T[1:-1], "ds": D[1:-1], "x": X[1:-1]}, Id="root")
    add(root, T + "SchemeInformation", "owned service claim")
    signature = add(root, D + "Signature", Id="signature")
    info = add(signature, D + "SignedInfo")
    add(info, D + "CanonicalizationMethod", Algorithm=inspect.C14N)
    add(info, D + "SignatureMethod", Algorithm=inspect.RSA512)
    for attrs, algorithms in (
        ({"Id": "document", "URI": ""}, (inspect.ENVELOPED, inspect.C14N)),
        ({"Type": inspect.PROPERTIES, "URI": "#properties"}, (inspect.C14N,)),
    ):
        ref = add(info, D + "Reference", **attrs)
        transforms = add(ref, D + "Transforms")
        for uri in algorithms:
            add(transforms, D + "Transform", Algorithm=uri)
        add(ref, D + "DigestMethod", Algorithm=inspect.SHA512)
        add(ref, D + "DigestValue")
    add(signature, D + "SignatureValue", Id="signature-value")
    add(add(signature, D + "KeyInfo"), D + "X509Data")
    add(signature[2][0], D + "X509Certificate", encoded(cert))
    qualifying = add(add(signature, D + "Object"), X + "QualifyingProperties", Target="#signature")
    properties = add(qualifying, X + "SignedProperties", Id="properties")
    signing = add(properties, X + "SignedSignatureProperties")
    add(signing, X + "SigningTime", "2020-01-01T12:00:00Z")
    signing_cert = add(add(signing, X + "SigningCertificateV2"), X + "Cert")
    digest = add(signing_cert, X + "CertDigest")
    add(digest, D + "DigestMethod", Algorithm=inspect.SHA512)
    add(digest, D + "DigestValue", encoded(hashlib.sha512(cert).digest()))
    add(signing_cert, X + "IssuerSerialV2", "uninterpreted signed bytes")
    data = add(add(properties, X + "SignedDataObjectProperties"), X + "DataObjectFormat", ObjectReference="#document")
    add(data, X + "MimeType", "text/xml")
    return root, key, hashlib.sha256(cert).hexdigest()


def signed(owned, *, tail=None):
    template, key, pin = owned
    root = copy.deepcopy(template)
    signature = root.find(D + "Signature")
    signature.tail = tail
    # Independent fixture construction: the document without Signature is prepared
    # before signing; signed tail text is deliberately placed after SchemeInformation.
    document = copy.deepcopy(root)
    document.remove(document.find(D + "Signature"))
    if tail:
        document[-1].tail = (document[-1].tail or "") + tail
    properties = signature.find(".//" + X + "SignedProperties")
    info = signature[0]
    for ref, node in zip(info[2:], (document, properties), strict=True):
        ref[2].text = encoded(hashlib.sha512(c14n(node)).digest())
    signature[1].text = encoded(key.sign(c14n(info), padding.PKCS1v15(), hashes.SHA512()))
    return root, pin


def test_valid_replay_has_no_time_or_provider_authority(owned, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("offline inspection attempted external operation")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    root, pin = signed(owned)
    wire = etree.tostring(root)
    report = inspect.inspect_xml(wire, pin)
    assert report == inspect.inspect_xml(wire, pin)
    assert report["input_sha256"] == hashlib.sha256(wire).hexdigest()
    assert report["signature_under_supplied_pin"] == "verified"
    assert all(
        report[field] is False
        for field in (
            "kernel_authority",
            "provider_admitted",
            "currentness_established",
            "revocation_checked",
            "legal_qualification_established",
        )
    )


@pytest.mark.parametrize("tail", ["\n  ", "signed tail"])
def test_signature_tail_is_signed_and_preserved(owned, tail):
    root, pin = signed(owned, tail=tail)
    assert inspect.inspect_xml(etree.tostring(root), pin)["signature_under_supplied_pin"] == "verified"
    root[-1].tail = tail + "tampered"
    with pytest.raises(ValueError, match="reference digest"):
        inspect.inspect_xml(etree.tostring(root), pin)


@pytest.mark.parametrize(
    "case",
    [
        "body",
        "property",
        "pin",
        "signature",
        "certificate",
        "signed_certificate_digest",
        "document_digest",
        "duplicate_id",
        "alternate_id",
        "nested_signature",
        "second_signature",
        "extra_reference",
        "external_uri",
        "properties_uri",
        "properties_type",
        "signature_target",
        "data_reference",
        "transform",
        "transform_parameter",
        "c14n",
        "signature_algorithm",
        "digest_algorithm",
        "root",
        "key_info",
        "unsigned_properties",
        "comment",
        "processing_instruction",
        "encoded_child",
        "encoded_attribute",
        "noncanonical_base64",
        "structural_text",
        "structural_tail",
        "duplicate_properties",
        "signature_attribute",
    ],
)
def test_tampering_and_ambiguous_structure_refuse(owned, case):
    root, pin = signed(owned)
    signature = root.find(D + "Signature")
    info = signature[0]
    properties = signature.find(".//" + X + "SignedProperties")
    if case == "body":
        root[0].text = "changed service"
    elif case == "property":
        properties[0][0].text = "2026-01-01T00:00:00Z"
    elif case == "pin":
        pin = "0" * 64
    elif case == "signature":
        signature[1].text = encoded(b"\0" * 256)
    elif case == "certificate":
        signature[2][0][0].text = encoded(b"changed certificate")
    elif case == "signed_certificate_digest":
        properties[0][1][0][0][1].text = encoded(b"\0" * 64)
    elif case == "document_digest":
        info[2][2].text = encoded(b"\0" * 64)
    elif case == "duplicate_id":
        root[0].set("Id", "properties")
    elif case == "alternate_id":
        root[0].set("{http://www.w3.org/XML/1998/namespace}id", "alias")
    elif case == "nested_signature":
        root.remove(signature)
        root[0].append(signature)
    elif case == "second_signature":
        root.append(copy.deepcopy(signature))
    elif case == "extra_reference":
        info.append(copy.deepcopy(info[2]))
    elif case == "external_uri":
        info[2].set("URI", "https://invalid.example/document")
    elif case == "properties_uri":
        info[3].set("URI", "#root")
    elif case == "properties_type":
        info[3].set("Type", "other")
    elif case == "signature_target":
        signature[3][0].set("Target", "#root")
    elif case == "data_reference":
        properties[1][0].set("ObjectReference", "#root")
    elif case == "transform":
        info[2][0][0].set("Algorithm", "http://www.w3.org/TR/1999/REC-xslt-19991116")
    elif case == "transform_parameter":
        add(info[3][0][0], "parameter")
    elif case == "c14n":
        info[0].set("Algorithm", inspect.C14N + "WithComments")
    elif case == "signature_algorithm":
        info[1].set("Algorithm", "rsa-sha1")
    elif case == "digest_algorithm":
        info[2][1].set("Algorithm", "sha1")
    elif case == "root":
        root.tag = "wrapper"
    elif case == "key_info":
        add(signature[2], D + "RetrievalMethod", URI="file:///private")
    elif case == "unsigned_properties":
        add(signature[3][0], X + "UnsignedProperties")
    elif case == "comment":
        root.insert(0, etree.Comment("unsigned comment"))
    elif case == "processing_instruction":
        root.insert(0, etree.ProcessingInstruction("xml-stylesheet", 'href="file"'))
    elif case == "encoded_child":
        add(info[2][2], "child")
    elif case == "encoded_attribute":
        info[2][2].set("Id", "digest-id")
    elif case == "noncanonical_base64":
        info[2][2].text += "="
    elif case == "structural_text":
        info.text = "extra"
    elif case == "structural_tail":
        info[0].tail = "extra"
    elif case == "duplicate_properties":
        signature[3][0].append(copy.deepcopy(properties))
    elif case == "signature_attribute":
        signature.set("other", "value")
    with pytest.raises((ValueError, InvalidSignature, etree.LxmlError)):
        inspect.inspect_xml(etree.tostring(root), pin)


@pytest.mark.parametrize(
    "prefix",
    [
        b'<!DOCTYPE TrustServiceStatusList [<!ENTITY a SYSTEM "file:///etc/passwd">]>',
        b'<!DOCTYPE TrustServiceStatusList SYSTEM "https://invalid.example/dtd">',
        b"<?outside-root instruction?>",
        b"<!--outside root-->",
    ],
)
def test_external_entities_and_outside_root_nodes_refuse(owned, prefix):
    root, pin = signed(owned)
    with pytest.raises(ValueError):
        inspect.inspect_xml(prefix + etree.tostring(root), pin)


@pytest.mark.parametrize("limit", ["MAX_BYTES", "MAX_NODES", "MAX_DEPTH", "MAX_CANONICAL"])
def test_resource_limits_refuse(owned, monkeypatch, limit):
    root, pin = signed(owned)
    monkeypatch.setattr(inspect, limit, 1)
    with pytest.raises(ValueError, match="bound"):
        inspect.inspect_xml(etree.tostring(root), pin)


@pytest.mark.parametrize("pin", [None, True, "", "0" * 63, "A" * 64])
def test_malformed_pin_refuses(owned, pin):
    root, _ = signed(owned)
    with pytest.raises(ValueError, match="pin syntax"):
        inspect.inspect_xml(etree.tostring(root), pin)


def test_non_utf8_refuses(owned):
    root, pin = signed(owned)
    with pytest.raises(ValueError):
        inspect.inspect_xml(etree.tostring(root, encoding="UTF-16"), pin)


def test_wrong_signing_key_refuses(owned):
    root, pin = signed(owned)
    signature = root.find(D + "Signature")
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signature[1].text = encoded(other.sign(c14n(signature[0]), padding.PKCS1v15(), hashes.SHA512()))
    with pytest.raises(InvalidSignature):
        inspect.inspect_xml(etree.tostring(root), pin)


def test_same_key_different_certificate_and_new_pin_still_refuses(owned):
    root, _ = signed(owned)
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Substituted identity")])
    key = owned[1]
    other = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(8)
        .not_valid_before(datetime(2020, 1, 1, tzinfo=UTC))
        .not_valid_after(datetime(2020, 1, 2, tzinfo=UTC))
        .sign(key, hashes.SHA256())
    ).public_bytes(serialization.Encoding.DER)
    root.find(D + "Signature")[2][0][0].text = encoded(other)
    with pytest.raises(ValueError, match="signed certificate digest"):
        inspect.inspect_xml(etree.tostring(root), hashlib.sha256(other).hexdigest())


def test_weak_rsa_fixture_refuses_even_valid_signature(owned):
    template, _, _ = owned
    template = copy.deepcopy(template)
    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Owned unsupported weak key")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(weak.public_key())
        .serial_number(9)
        .not_valid_before(datetime(2020, 1, 1, tzinfo=UTC))
        .not_valid_after(datetime(2020, 1, 2, tzinfo=UTC))
        .sign(weak, hashes.SHA256())
    ).public_bytes(serialization.Encoding.DER)
    template.find(D + "Signature")[2][0][0].text = encoded(cert)
    template.find(".//" + X + "CertDigest")[1].text = encoded(hashlib.sha512(cert).digest())
    root, pin = signed((template, weak, hashlib.sha256(cert).hexdigest()))
    with pytest.raises(ValueError, match="unsupported signing key"):
        inspect.inspect_xml(etree.tostring(root), pin)


def test_cli_agrees_and_refuses_wrong_pin(owned, tmp_path, capsys):
    root, pin = signed(owned)
    wire = etree.tostring(root)
    path = tmp_path / "owned.xml"
    path.write_bytes(wire)
    assert inspect.main([str(path), "--signer-sha256", pin]) == 0
    assert json.loads(capsys.readouterr().out) == inspect.inspect_xml(wire, pin)
    assert inspect.main([str(path), "--signer-sha256", "0" * 64]) == 2
    assert "pin differs" in capsys.readouterr().err
