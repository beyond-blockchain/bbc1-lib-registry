# -*- coding: utf-8 -*-
import hashlib
import sys
import time
import xml.etree.ElementTree as ET

sys.path.extend(["../"])

from bbc1.core import bbc_app
from bbc1.core import bbclib
from bbc1.core.bbc_config import DEFAULT_CORE_PORT
from bbc1.lib import id_lib, registry_lib

domain_id = None
registry_id = None
idPubkeyMap = None
keypairs = None


def setup():
    global domain_id
    global registry_id
    global idPubkeyMap
    global keypairs

    domain_id = bbclib.get_new_id("test_registry", include_timestamp=False)

    tmpclient = bbc_app.BBcAppClient(port=DEFAULT_CORE_PORT, multiq=False,
            loglevel="all")
    tmpclient.domain_setup(domain_id)
    tmpclient.callback.synchronize()
    tmpclient.unregister_from_core()

    idPubkeyMap = id_lib.BBcIdPublickeyMap(domain_id)
    registry_id, keypairs = idPubkeyMap.create_user_id(num_pubkeys=1)


def test_document_spec():

#   description can be any meta data for a document, such as a string,
#   a dict, or just an arbitrary binary.

    description = "Driver's License"
    expire_at = 1552640400

    document_spec_dict = {
        'description': description,
        'expire_at': expire_at,
        'option_updatable': False,
    }

    spec = registry_lib.DocumentSpec(document_spec_dict)

    assert spec.description == description
    assert spec.expire_at == expire_at
    assert spec.option_updatable == False

    spec1 = registry_lib.DocumentSpec(document_spec_dict)

    assert spec1 == spec

    dat = spec1.serialize()
    _, spec2 = registry_lib.DocumentSpec.from_serialized_data(0, dat)

    assert spec2 == spec1 == spec

    document_spec_dict = {
        'description': b'just any binary',
    }

    spec = registry_lib.DocumentSpec(document_spec_dict)

    assert not spec2 == spec

    assert spec.description == b'just any binary'
    assert spec.expire_at == 0
    assert spec.option_updatable == True

    dat = spec.serialize()
    _, spec2 = registry_lib.DocumentSpec.from_serialized_data(0, dat)

    assert spec2 == spec

    document_id = bbclib.get_new_id("sample document 1")

    descriptin = {
        'type': "Driver's License",
        'identity': document_id,
    }

    document_spec_dict = {
        'description': description
    }

    spec = registry_lib.DocumentSpec(document_spec_dict)

    assert spec.description == description

    spec1 = registry_lib.DocumentSpec(document_spec_dict)

    assert spec1 == spec

    dat = spec1.serialize()
    _, spec2 = registry_lib.DocumentSpec.from_serialized_data(0, dat)

    assert spec.description == spec1.description
    assert spec1.description == spec2.description

    assert spec2 == spec1 == spec

    document_spec_dict = {
        'description': 123,
    }

    try:
        spec = registry_lib.DocumentSpec(document_spec_dict)
    except TypeError:
        spec = 10

    assert spec == 10

    document_spec_dict = {
        'description': "Driver's License",
        'expire_at': "never",
    }

    try:
        spec = registry_lib.DocumentSpec(document_spec_dict)
    except TypeError:
        spec = 11

    assert spec == 11

    document_spec_dict = {
        'description': "Driver's License",
        'expire_at': -1
    }

    try:
        spec = registry_lib.DocumentSpec(document_spec_dict)
    except TypeError:
        spec = 12

    assert spec == 12

    document_spec_dict = {
        'description': "Driver's License",
        'option_updatable': "yes",
    }

    try:
        spec = registry_lib.DocumentSpec(document_spec_dict)
    except TypeError:
        spec = 13

    assert spec == 13


def test_document():

    xml_string = "<doc>" + \
            "<sec>Today,</sec>" + \
            "<sec>I am</sec>" + \
            "<sec>what I am.</sec>" + \
            "</doc>"

    document = registry_lib.Document.from_xml_string(xml_string)

    assert len(document.root) == 3
    assert document.root[0].text == "Today,"
    assert document.root[1].text == "I am"
    assert document.root[2].text == "what I am."

    dat = bytearray()
    dat.extend(hashlib.sha256(ET.tostring(document.root[0],
            encoding="utf-8")).digest())
    dat.extend(hashlib.sha256(ET.tostring(document.root[1],
            encoding="utf-8")).digest())
    dat.extend(hashlib.sha256(ET.tostring(document.root[2],
            encoding="utf-8")).digest())

    assert document.file() == bytes(dat)


def test_registry():

    registry = registry_lib.BBcRegistry(domain_id, registry_id, registry_id,
            idPubkeyMap)

    user_a_id, keypairs_a = idPubkeyMap.create_user_id(num_pubkeys=1)
    user_b_id, keypairs_b = idPubkeyMap.create_user_id(num_pubkeys=1)

    xml_string = "<doc>" + \
            "<sec>I don't remember if you can Cossack dance.</sec>" + \
            "<sec>I don't remember how much it is.</sec>" + \
            "<sec>The strawberry girl is an only child.</sec>" + \
            "</doc>"

    document = registry_lib.Document.from_xml_string(xml_string)
    document.set_document_id(bbclib.get_new_id("sample document 1"))

    dat = bytearray()
    dat.extend(hashlib.sha256(ET.tostring(document.root[0],
            encoding="utf-8")).digest())
    dat.extend(hashlib.sha256(ET.tostring(document.root[1],
            encoding="utf-8")).digest())
    dat.extend(hashlib.sha256(ET.tostring(document.root[2],
            encoding="utf-8")).digest())

    digest = hashlib.sha256(bytes(dat)).digest()

    document_spec = registry_lib.DocumentSpec(description="Hitorikko")

    registry.register_document(user_a_id, document, document_spec,
            keypair=keypairs[0])

    assert registry.get_document_digest(document.document_id) == digest

    assert registry.get_document_spec(document.document_id) == document_spec

    document_spec_dict = {
        'description': {
            'note': "hey hey hey",
            'proof': "23942398948594898854345",
        },
        'expire_at': 1552640400,
        'option_updatable': True,
    }

    document_spec = registry_lib.DocumentSpec(document_spec_dict)

    registry.update_document(user_a_id, user_b_id, document,
            document_spec=document_spec,
            keypair=keypairs_a[0], keypair_registry=keypairs[0])

    assert registry.get_document_digest(document.document_id) == digest
    assert registry.get_document_spec(document.document_id) == document_spec

    document.root[1].text = "How much is it?"

    dat = bytearray()
    dat.extend(hashlib.sha256(ET.tostring(document.root[0],
            encoding="utf-8")).digest())
    dat.extend(hashlib.sha256(ET.tostring(document.root[1],
            encoding="utf-8")).digest())
    dat.extend(hashlib.sha256(ET.tostring(document.root[2],
            encoding="utf-8")).digest())

    assert document.file() == bytes(dat)

    digest2 = hashlib.sha256(bytes(dat)).digest()

    assert not registry.get_document_digest(document.document_id) == digest2

    registry.update_document(user_b_id, user_b_id, document,
            keypair=keypairs_b[0], keypair_registry=keypairs[0])

    assert registry.get_document_digest(document.document_id) == digest2
    assert registry.get_document_spec(document.document_id) == document_spec

    document_spec = registry_lib.DocumentSpec(option_updatable=False)

    registry.update_document(user_b_id, user_b_id, document,
            document_spec=document_spec,
            keypair=keypairs_b[0], keypair_registry=keypairs[0])

    assert registry.get_document_digest(document.document_id) == digest2
    assert registry.get_document_spec(document.document_id) == document_spec

    try:
        registry.update_document(user_b_id, user_b_id, document,
                keypair=keypairs_b[0], keypair_registry=keypairs[0])
    except:
        document_spec = 0

    assert document_spec == 0


# end of tests/test_registry_lib.py
