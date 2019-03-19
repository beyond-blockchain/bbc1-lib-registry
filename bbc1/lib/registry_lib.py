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
import hashlib
import sys
import time
import xml.etree.ElementTree as ET

sys.path.append("../../")

from bbc1.core import bbclib
from bbc1.core.libs import bbclib_utils
from bbc1.core import logger, bbc_app
from bbc1.core.bbc_error import *
from bbc1.core.message_key_types import KeyType
from bbc1.core.bbc_config import DEFAULT_CORE_PORT
from bbc1.lib import app_support_lib


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
    ["is_single", "INTEGER"],
    ["state", "INTEGER"],
    ["last_modified", "INTEGER"]
]

IDX_REGISTRY_ID     = 0
IDX_TX_ID           = 1
IDX_EVENT_IDX       = 2
IDX_DOCUMENT_ID     = 3
IDX_DOCUMENT_DIGEST = 4
IDX_IS_SINGLE       = 5
IDX_STATE           = 6
IDX_LAST_MODIFIED   = 7

ST_FREE     = 0
ST_RESERVED = 1
ST_TAKEN    = 2


class Constants(app_support_lib.Constants):

    VERSION_CURRENT = 0


class Document:

    def __init__(self, document_id=None, root=None):
        self.document_id = document_id
        self.root = root


    def file(self):
        dat = bytearray()
        for e in self.root:
            string = e.text.encode()
            dat.extend(hashlib.sha256(string).digest())
        return bytes(dat)


    @staticmethod
    def from_xml_string(string):
        return Document(root=ET.fromstring(string))


    def set_document_id(self, document_id):
        self.document_id = document_id


class Store:

    def __init__(self, domain_id, registry_id, app):
        self.domain_id = domain_id
        self.registry_id = registry_id
        self.app = app
        self.db_online = True
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
        self.independent = False


    def delete_utxo(self, tx_id, idx):
        if self.db_online is False:
            return None
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
        if self.db_online is False:
            return None
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
                        event.asset.asset_file_digest, True)

        for ref in tx.references:
            if ref.asset_group_id == self.registry_id:
                self.delete_utxo(ref.transaction_id, ref.event_index_in_ref)


    def push_tx(self, tx_id, tx):
        if self.db_online is False:
            return
        self.db.exec_sql(
            self.domain_id,
            NAME_OF_DB,
            'insert into registry_tx_id_table values (?, ?)',
            tx_id,
            bbclib.serialize(tx)
        )


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
        if self.db_online is False:
            return None
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


    '''
    mainly for testing purposes.
    '''
    def set_db_online(self, is_online=True):
        self.db_online = is_online


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
        if self.db_online is False:
            return None
        rows = self.db.exec_sql(
            self.domain_id,
            NAME_OF_DB,
            'select tx from registry_tx_id_table where tx_id=?',
            tx_id
        )
        if len(rows) <= 0:
            return None
        tx, fmt = bbclib.deserialize(rows[0][0])
        if self.independent:
            self.db.exec_sql(
                self.domain_id,
                NAME_OF_DB,
                'delete from registry_tx_id_table where tx_id=?',
                tx_id
            )
        return tx


    def write_utxo(self, tx_id, idx, document_id, document_digest, is_single):
        if self.db_online is False:
            return
        self.db.exec_sql(
            self.domain_id,
            NAME_OF_DB,
            'insert into registry_table values (?, ?, ?, ?, ?, ?, ?, ?)',
            self.registry_id,
            tx_id,
            idx,
            document_id,
            document_digest,
            is_single,
            ST_FREE,
            int(time.time())
        )


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


    def register_document(self, user_id, document, note=None, keypair=None):
        if self.user_id != self.registry_id:
            raise RuntimeError('registerer must be the registry')

        tx = bbclib.make_transaction(event_num=1)
        tx.events[0].asset_group_id = self.registry_id
        tx.events[0].asset.add(user_id=document.document_id,
                asset_file=document.file(), asset_body=note)

        tx.events[0].add(mandatory_approver=self.registry_id)
        tx.events[0].add(mandatory_approver=user_id)
        tx.add(witness=bbclib.BBcWitness())
        tx.witness.add_witness(self.registry_id)

        if keypair is None:
            return tx

        return self.store.sign_and_insert(tx, self.registry_id,
                keypair, self.idPublickeyMap)


    def make_event(self, ref_indices, user_id, document, note=None):
        event = bbclib.BBcEvent(asset_group_id=self.registry_id)
        for i in ref_indices:
            event.add(reference_index=i)
        event.add(mandatory_approver=self.registry_id)
        event.add(mandatory_approver=user_id)
        event.add(asset=bbclib.BBcAsset())
        event.asset.add(user_id=document.document_id,
                asset_file=document.file(), asset_body=note)
        return event


    def set_keypair(self, keypair):
       self.app.callback.set_keypair(keypair)


    def sign_and_insert(self, transaction, user_id, keypair):
        return self.store.sign_and_insert(transaction, user_id, keypair,
                self.idPublickeyMap)


    def update_document(self, user_id, new_user_id, document, note=None,
            transaction=None, keypair=None, keypair_registry=None):
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
        tx.add(event=self.make_event([base_refs], new_user_id, document, note))

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
