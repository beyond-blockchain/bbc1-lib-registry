# -*- coding: utf-8 -*-
import hashlib
import sys
import time

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

    domain_id = bbclib.get_new_id("test_registry_lib", include_timestamp=False)

    tmpclient = bbc_app.BBcAppClient(port=DEFAULT_CORE_PORT, multiq=False,
            loglevel="all")
    tmpclient.domain_setup(domain_id)
    tmpclient.callback.synchronize()
    tmpclient.unregister_from_core()

    idPubkeyMap = id_lib.BBcIdPublickeyMap(domain_id)
    registry_id, keypairs = idPubkeyMap.create_user_id(num_pubkeys=1)


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
    dat.extend(hashlib.sha256(document.root[0].text.encode()).digest())
    dat.extend(hashlib.sha256(document.root[1].text.encode()).digest())
    dat.extend(hashlib.sha256(document.root[2].text.encode()).digest())

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
    dat.extend(hashlib.sha256(document.root[0].text.encode()).digest())
    dat.extend(hashlib.sha256(document.root[1].text.encode()).digest())
    dat.extend(hashlib.sha256(document.root[2].text.encode()).digest())

    digest = hashlib.sha256(bytes(dat)).digest()

    registry.register_document(user_a_id, document, keypair=keypairs[0])

    assert registry.get_document_digest(document.document_id) == digest

    registry.update_document(user_a_id, user_b_id, document,
            keypair=keypairs_a[0], keypair_registry=keypairs[0])

    assert registry.get_document_digest(document.document_id) == digest

    document.root[1].text = "How much is it?"

    dat = bytearray()
    dat.extend(hashlib.sha256(document.root[0].text.encode()).digest())
    dat.extend(hashlib.sha256(document.root[1].text.encode()).digest())
    dat.extend(hashlib.sha256(document.root[2].text.encode()).digest())

    assert document.file() == bytes(dat)

    digest2 = hashlib.sha256(bytes(dat)).digest()

    assert not registry.get_document_digest(document.document_id) == digest2

    registry.update_document(user_b_id, user_b_id, document,
            keypair=keypairs_b[0], keypair_registry=keypairs[0])

    assert registry.get_document_digest(document.document_id) == digest2


# end of tests/test_registry_lib.py
