# -*- coding: utf-8 -*-
"""
Copyright (c) 2019 beyond-blockchain.org.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
import binascii
import hashlib
import msgpack
import string
import sys
import threading
import time
import xml.etree.ElementTree as ET

sys.path.append("../../")

from bbc1.core import bbclib
from bbc1.core import logger, bbc_app
from bbc1.core.bbc_error import *
from bbc1.core.message_key_types import KeyType
from bbc1.core.bbc_config import DEFAULT_CORE_PORT
from bbc1.lib import app_support_lib
from bbclib.libs import bbclib_utils


NAME_OF_DB = 'registry_db'

registry_tx_id_table_definition = [
    ["tx_id", "BLOB"],
    ["tx", "BLOB"],
]

registry_table_definition = [
    ["registry_id", "BLOB"],
    ["tx_id", "BLOB"],
    ["event_idx", "INTEGER"],
    ["document_id", "BLOB"],
    ["document_digest", "BLOB"],
    ["document_spec", "BLOB"],
    ["is_single", "INTEGER"],
    ["state", "INTEGER"],
    ["last_modified", "INTEGER"]
]

IDX_REGISTRY_ID     = 0
IDX_TX_ID           = 1
IDX_EVENT_IDX       = 2
IDX_DOCUMENT_ID     = 3
IDX_DOCUMENT_DIGEST = 4
IDX_DOCUMENT_SPEC   = 5
IDX_IS_SINGLE       = 6
IDX_STATE           = 7
IDX_LAST_MODIFIED   = 8

ST_FREE     = 0
ST_RESERVED = 1
ST_TAKEN    = 2


class Constants(app_support_lib.Constants):

    DESC_BINARY     = 0
    DESC_DICTIONARY = 1
    DESC_STRING     = 2

    O_BIT_UPDATABLE = 0b0000000000000001

    VERSION_CURRENT = 0


class DocumentSpec:

    def __init__(self, dic=None, description=None, expire_at=0,
            option_updatable=True,
            version=Constants.VERSION_CURRENT):
        self.version = version

        if dic is not None:
            try:
                description = dic['description']
            except KeyError:
                description = None
        if description is not None:
            if isinstance(description, str):
                raw = description.encode()
            elif isinstance(description, dict):
                raw = msgpack.dumps(description, encoding='utf-8')
            else:
                raw = description
            if len(raw) > Constants.MAX_INT16:
                raise TypeError('description is too long')
        self.description = description

        if dic is not None:
            try:
                expire_at = dic['expire_at']
            except KeyError:
                expire_at = 0
        if not isinstance(expire_at, int):
            raise TypeError('expire_at must be int')
        if expire_at < 0 or expire_at > Constants.MAX_INT64:
            raise TypeError('expire_at out of range')
        self.expire_at = expire_at

        if dic is not None:
            try:
                option_updatable = dic['option_updatable']
            except KeyError:
                option_updatable = True
        if not isinstance(option_updatable, bool):
            raise TypeError('this option must be bool')
        self.option_updatable = option_updatable

    def __eq__(self, other):
        if isinstance(other, DocumentSpec):
            if self.description != other.description \
                    or self.expire_at != other.expire_at \
                    or self.option_updatable != other.option_updatable:
                return False
            return True
        else:
            return False


    @staticmethod
    def from_serialized_data(ptr, data):
        try:
            ptr, version = bbclib_utils.get_n_byte_int(ptr, 2, data)
            ptr, t = bbclib_utils.get_n_byte_int(ptr, 1, data)
            ptr, size = bbclib_utils.get_n_byte_int(ptr, 2, data)
            if size > 0:
                ptr, v = bbclib_utils.get_n_bytes(ptr, size, data)
                if t == Constants.DESC_STRING:
                    description = v.decode()
                elif t == Constants.DESC_DICTIONARY:
                    description = msgpack.loads(v, encoding='utf-8')
                else:
                    description = v
            else:
                description = None
            ptr, expire_at = bbclib_utils.get_n_byte_int(ptr, 8, data)
            ptr, v = bbclib_utils.get_n_byte_int(ptr, 2, data)
            option_updatable = v & Constants.O_BIT_UPDATABLE != 0
        except:
            raise
        return ptr, DocumentSpec(description=description, expire_at=expire_at,
                option_updatable=option_updatable, version=version)


    def is_updatable(self):
        return self.option_updatable


    def serialize(self):
        dat = bytearray(bbclib_utils.to_2byte(self.version))
        if self.description is None:
            dat.extend(bbclib_utils.to_1byte(Constants.DESC_BINARY))
            dat.extend(bbclib_utils.to_2byte(0))
        elif isinstance(self.description, str):
            dat.extend(bbclib_utils.to_1byte(Constants.DESC_STRING))
            string = self.description.encode()
            dat.extend(bbclib_utils.to_2byte(len(string)))
            dat.extend(string)
        elif isinstance(self.description, dict):
            dat.extend(bbclib_utils.to_1byte(Constants.DESC_DICTIONARY))
            raw = msgpack.dumps(self.description, encoding='utf-8')
            dat.extend(bbclib_utils.to_2byte(len(raw)))
            dat.extend(raw)
        else:
            dat.extend(bbclib_utils.to_1byte(Constants.DESC_BINARY))
            dat.extend(bbclib_utils.to_2byte(len(self.description)))
            dat.extend(self.description)
        dat.extend(bbclib_utils.to_8byte(self.expire_at))

        options = Constants.O_BIT_NONE
        if self.option_updatable:
            options |= Constants.O_BIT_UPDATABLE
        dat.extend(bbclib_utils.to_2byte(options))
        return bytes(dat)


class Document:

    def __init__(self, document_id=None, root=None):
        self.document_id = document_id
        self.root = root


    def file(self):

        dat = bytearray()
        for e in self.root:
            if e.tag == 'digest':
                digest = binascii.a2b_hex(e.text)
                dat.extend(digest)
            else:
                string = ET.tostring(e, encoding="utf-8")
                dat.extend(hashlib.sha256(string).digest())

        return bytes(dat)


    @staticmethod
    def from_xml_string(string):
        return Document(root=ET.fromstring(string))


    def set_document_id(self, document_id):
        self.document_id = document_id


class Store:

    lock = threading.Lock()


    def __init__(self, domain_id, registry_id, app):
        self.domain_id = domain_id
        self.registry_id = registry_id
        self.app = app
        self.db = app_support_lib.Database()
        self.db.setup_db(domain_id, NAME_OF_DB)
        self.db.create_table_in_db(domain_id, NAME_OF_DB,
                'registry_table',
                registry_table_definition,
                indices=[0, 1, 3])
        self.db.create_table_in_db(domain_id, NAME_OF_DB,
                'registry_tx_id_table',
                registry_tx_id_table_definition,
                primary_key=0, indices=[1])


    def delete_utxo(self, tx_id, idx):
        return self.db.exec_sql(
            self.domain_id,
            NAME_OF_DB,
            ('update registry_table set state=?, last_modified=? where '
             'tx_id=? and event_idx=?'),
            ST_TAKEN,
            int(time.time()),
            tx_id,
            idx
        )


    def get_document_digest(self, document_id, eval_time=None):
        rows = self.db.exec_sql(
            self.domain_id,
            NAME_OF_DB,
            ('select document_digest from registry_table where '
             'registry_id=? and document_id=? and state=?'),
            self.registry_id,
            document_id,
            ST_FREE
        )
        if len(rows) <= 0:
            return None
        return rows[0][0]


    def get_document_spec(self, document_id, eval_time=None):
        rows = self.db.exec_sql(
            self.domain_id,
            NAME_OF_DB,
            ('select document_spec from registry_table where '
             'registry_id=? and document_id=? and state=?'),
            self.registry_id,
            document_id,
            ST_FREE
        )
        if len(rows) <= 0:
            return None
        _, spec = DocumentSpec.from_serialized_data(0, rows[0][0])
        return spec


    def get_tx(self, tx_id):
        self.app.search_transaction(tx_id)
        res = self.app.callback.synchronize()
        if res[KeyType.status] < ESUCCESS:
            raise ValueError('not found')
        tx, fmt = bbclib.deserialize(res[KeyType.transaction_data])
        return tx


    def get_usable_event(self, document_id):
        rows = self.read_utxo(document_id)
        if len(rows) <= 0:
            raise
        tx_id = rows[0][IDX_TX_ID]
        index = rows[0][IDX_EVENT_IDX]
        return self.get_tx(tx_id), index


    def insert(self, tx, user_id, idPublickeyMap):
        if idPublickeyMap.verify_signers(tx, self.registry_id,
                user_id) == False:
            raise RuntimeError('signers not verified')

        self.push_tx(tx.transaction_id, tx)
        ret = self.app.insert_transaction(tx)
        assert ret
        res = self.app.callback.synchronize()
        if res[KeyType.status] < ESUCCESS:
            raise RuntimeError(res[KeyType.reason].decode())


    def inserted(self, tx_id):
        tx = self.take_tx(tx_id)
        if tx is None:
            return

        # FIXME: check validity
        for i, event in enumerate(tx.events):
            if event.asset_group_id == self.registry_id:
                self.write_utxo(tx.transaction_id, i, event.asset.user_id,
                        event.asset.asset_file_digest, event.asset.asset_body,
                        True)

        for ref in tx.references:
            if ref.asset_group_id == self.registry_id:
                self.delete_utxo(ref.transaction_id, ref.event_index_in_ref)


    def push_tx(self, tx_id, tx):

        Store.lock.acquire()

        rows = self.db.exec_sql(
            self.domain_id,
            NAME_OF_DB,
            'select rowid from registry_tx_id_table where tx_id=?',
            tx_id
        )
        if len(rows) <= 0:
            self.db.exec_sql(
                self.domain_id,
                NAME_OF_DB,
                'insert into registry_tx_id_table values (?, ?)',
                tx_id,
                bbclib.serialize(tx)
            )

        Store.lock.release()


    def read_utxo(self, document_id):
        return self.db.exec_sql(
            self.domain_id,
            NAME_OF_DB,
            ('select * from registry_table where '
             'registry_id=? and document_id=? and state=?'),
            self.registry_id,
            document_id,
            ST_FREE
        )


    def reserve_utxo(self, tx_id, idx):
        return self.db.exec_sql(
            self.domain_id,
            NAME_OF_DB,
            ('update registry_table set state=?, last_modified=? where '
             'tx_id=? and event_idx=?'),
            ST_RESERVED,
            int(time.time()),
            tx_id,
            idx
        )


    def reserve_referred_utxos(self, tx):
        for ref in tx.references:
            if ref.asset_group_id == self.registry_id:
                self.reserve_utxo(ref.transaction_id, ref.event_index_in_ref)


    def sign(self, transaction, user_id, keypair):
        sig = transaction.sign(
                private_key=keypair.private_key,
                public_key=keypair.public_key)
        transaction.add_signature(user_id=user_id, signature=sig)
        return sig


    def sign_and_insert(self, transaction, user_id, keypair, idPublickeyMap):
        self.sign(transaction, user_id, keypair)
        transaction.digest()
        self.insert(transaction, user_id, idPublickeyMap)
        return transaction


    def take_tx(self, tx_id):
        rows = self.db.exec_sql(
            self.domain_id,
            NAME_OF_DB,
            'select tx from registry_tx_id_table where tx_id=?',
            tx_id
        )
        if len(rows) <= 0:
            return None
        tx, fmt = bbclib.deserialize(rows[0][0])
        return tx


    def write_utxo(self, tx_id, idx, document_id, document_digest,
         document_spec, is_single):

        Store.lock.acquire()

        rows = self.db.exec_sql(
            self.domain_id,
            NAME_OF_DB,
            'select rowid from registry_table where tx_id=? and event_idx=?',
            tx_id,
            idx
        )
        if len(rows) <= 0:
            self.db.exec_sql(
                self.domain_id,
                NAME_OF_DB,
                'insert into registry_table ' \
                'values (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                self.registry_id,
                tx_id,
                idx,
                document_id,
                document_digest,
                document_spec,
                is_single,
                ST_FREE,
                int(time.time())
            )

        Store.lock.release()


class BBcRegistry:

    def __init__(self, domain_id, registry_id, user_id, idPublickeyMap,
            port=DEFAULT_CORE_PORT, logname="-", loglevel="none"):
        self.logger = logger.get_logger(key="registry_lib", level=loglevel,
                                        logname=logname) # FIXME: use logger
        self.domain_id = domain_id
        self.registry_id = registry_id
        self.user_id = user_id
        self.idPublickeyMap = idPublickeyMap
        self.app = bbc_app.BBcAppClient(port=DEFAULT_CORE_PORT,
                multiq=False, loglevel=loglevel)
        self.app.set_user_id(user_id)
        self.app.set_domain_id(domain_id)
        self.app.set_callback(RegistryCallback(logger, self))
        ret = self.app.register_to_core()
        assert ret

        self.store = Store(self.domain_id, self.registry_id, self.app)
        self.app.request_insert_completion_notification(self.registry_id)


    def get_document_digest(self, document_id, eval_time=None):
        return self.store.get_document_digest(document_id, eval_time)


    def get_document_spec(self, document_id, eval_time=None):
        return self.store.get_document_spec(document_id, eval_time)


    def register_document(self, user_id, document, document_spec,
        keypair=None):
        if self.user_id != self.registry_id:
            raise RuntimeError('registerer must be the registry')

        tx = bbclib.make_transaction(event_num=1)
        tx.events[0].asset_group_id = self.registry_id
        tx.events[0].asset.add(user_id=document.document_id,
                asset_file=document.file(),
                asset_body=document_spec.serialize())

        tx.events[0].add(mandatory_approver=self.registry_id)
        tx.events[0].add(mandatory_approver=user_id)
        tx.add(witness=bbclib.BBcWitness())
        tx.witness.add_witness(self.registry_id)

        if keypair is None:
            return tx

        return self.store.sign_and_insert(tx, self.registry_id,
                keypair, self.idPublickeyMap)


    def make_event(self, ref_indices, user_id, document, document_spec):
        event = bbclib.BBcEvent(asset_group_id=self.registry_id)
        for i in ref_indices:
            event.add(reference_index=i)
        event.add(mandatory_approver=self.registry_id)
        event.add(mandatory_approver=user_id)
        event.add(asset=bbclib.BBcAsset())
        event.asset.add(user_id=document.document_id,
                asset_file=document.file(),
                asset_body=document_spec.serialize())
        return event


    def set_keypair(self, keypair):
       self.app.callback.set_keypair(keypair)


    def sign_and_insert(self, transaction, user_id, keypair):
        return self.store.sign_and_insert(transaction, user_id, keypair,
                self.idPublickeyMap)


    def update_document(self, user_id, new_user_id, document,
            document_spec=None, transaction=None,
            keypair=None, keypair_registry=None):
        document_spec0 = self.get_document_spec(document.document_id)
        if document_spec0 is None:
            raise TypeError('document does not exist')
        if not document_spec0.is_updatable():
            raise TypeError('document is not updatable')

        if document_spec is None:
            document_spec = document_spec0

        if transaction is None:
            tx = bbclib.BBcTransaction()
            base_refs = 0
        else:
            tx = transaction
            base_refs = len(tx.references)

        ref_tx, index = self.store.get_usable_event(document.document_id)

        ref = bbclib.BBcReference(asset_group_id=self.registry_id,
                transaction=tx, ref_transaction=ref_tx,
                event_index_in_ref=index)
        tx.add(reference=ref)
        tx.add(event=self.make_event([base_refs], new_user_id, document,
                document_spec))

        if keypair is None:
            return tx

        if keypair_registry is None:
            self.app.gather_signatures(tx, destinations=[self.registry_id])
            res = self.app.callback.synchronize()
            if res[KeyType.status] < ESUCCESS:
                raise RuntimeError(res[KeyType.reason].decode())
            result = res[KeyType.result]
            tx.add_signature(self.registry_id, signature=result[2])
            return self.store.sign_and_insert(tx, user_id, keypair,
                    self.idPublickeyMap)

        self.store.sign(tx, user_id, keypair)

        return self.store.sign_and_insert(tx, self.registry_id,
                keypair_registry, self.idPublickeyMap)


class RegistryCallback(bbc_app.Callback):

    def __init__(self, logger, registry):
        super().__init__(logger)
        self.registry = registry
        self.keypair = None


    def proc_cmd_sign_request(self, dat):
        source_user_id = dat[KeyType.source_user_id]

        if self.keypair is None:
            self.registry.app.sendback_denial_of_sign(source_user_id,
                    'keypair is unset')

        tx, fmt = bbclib.deserialize(dat[KeyType.transaction_data])

        # FIXME: check validity

        sig = self.registry.store.sign(tx, self.registry.user_id, self.keypair)
        tx.digest()

        self.registry.store.reserve_referred_utxos(tx)
        self.registry.store.push_tx(tx.transaction_id, tx)
        self.registry.app.sendback_signature(source_user_id, tx.transaction_id,
                -1, sig)


    def proc_notify_inserted(self, dat):
        self.registry.store.inserted(dat[KeyType.transaction_id])


    def set_keypair(self, keypair):
        self.keypair = keypair


# end of registry_lib.py
