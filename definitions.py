import os
import hashlib
import json
from urllib.parse import urlparse
import time
import requests
import base64
import tkinter.messagebox as messagebox
from pyclamd import *
from math import ceil
import pickle
import subprocess
from time import strftime
import copy

class Blockchain:

    def __init__(self):
        self.current_transactions = []
        self.chain = []
        self.nodes = set()
        self.rpis = {}
        self.connected = False
        self.chain_updated = False

        # Create the genesis block
        self.new_block(previous_hash='1')

        # Define names for storage files
        self.nodes_filename = 'nodes.pkl'
        self.blockchain_filename = 'blockchain.pkl'
        self.rpis_filename = 'rpis.pkl'

    # Transaction type: 'message' (legacy) or 'device_registration' (Phase 1 anchor)
    def _is_device_registration(self, transaction):
        return transaction.get('type') == 'device_registration'

    def get_file_names(self):
        aux = []
        for block in self.chain:
            for transaction in block['transactions']:
                if self._is_device_registration(transaction):
                    continue
                aux.append(transaction.get('name', ''))
        return aux

    def print_chain(self):
        printchain = []
        auxchain = copy.deepcopy(self.chain)
        for block in auxchain:
            auxtime = strftime('%x %X', time.localtime(block["timestamp"]))
            for transaction in block["transactions"]:
                auxblock = {'block_index': block['index'], 'previous_hash': block['previous_hash'],
                            'block_hash': block['hash'], 'time_stamp': auxtime}
                if self._is_device_registration(transaction):
                    auxblock['type'] = 'device_registration'
                    auxblock['did_i'] = transaction['did_i']
                    auxblock['vc_hash'] = transaction['vc_hash']
                else:
                    auxblock['type'] = 'message'
                    auxblock['file_hash'] = transaction.get('file_hash')
                    auxblock['ct'] = transaction.get('ct')
                    auxblock['pi'] = transaction.get('pi')
                    auxblock['pk'] = transaction.get('pk')
                    auxblock['name'] = transaction.get('name')
                printchain.append(auxblock)
        # print("Print Chain", printchain)

    def print_transactions(self):
        if len(self.current_transactions) == 0:
            print("INFO - Currently there are no transactions")
        for transaction in self.current_transactions:
            if self._is_device_registration(transaction):
                print({'type': 'device_registration', 'did_i': transaction['did_i'], 'vc_hash': transaction['vc_hash']})
            else:
                aux_trans = {'type': 'message', 'name': transaction.get('name'), 'file_hash': transaction.get('file_hash'), 'pk': transaction.get('pk')}
                print(aux_trans)

    def send_updates(self, rpi_address, name, file, file_hash, ct, pi, pk):
        update = {
            'name': name,
            'file': file,
            'file_hash': file_hash,
            'ct': ct,
            'pi': pi,
            'pk': pk
        }

        try:
            # Send as JSON with proper headers
            headers = {'Content-Type': 'application/json'}
            request = requests.post("http://" + rpi_address + "/updates/new", json=update, headers=headers)
            print("Request Response Type: " + str(type(request.text)))
            print("Request Response: " + request.text[:200])  # Fixed: show first 200 chars

        except requests.exceptions.Timeout as e:
            print("ERROR: RPi " + rpi_address + " - Timeout " + str(e))
            return False
        except requests.exceptions.ConnectionError:
            print("ERROR: RPi " + rpi_address + " - Failed to establish connection")
            return False

        self.rpis[rpi_address] = {'file_hash': file_hash, 'name': name, 'date': time.time(), 'status': 'OK'}
        return True

    def manage_updates(self):

        last_block = self.chain[len(self.chain)-1]
        for transaction in last_block['transactions']:
            if self._is_device_registration(transaction):
                continue  # Device registration anchors are not pushed as message updates

            _name = transaction['name']
            _file = transaction['file']
            _file_hash = transaction['file_hash']  # Fixed: correct key name
            _ct = transaction['ct']
            _pi = transaction['pi']
            _pk = transaction['pk']

            #Check what RPi needs this update and send it to them
            for r in self.rpis:
                if not 'hash' in self.rpis[r]:
                    self.send_updates(r.title(), _name, _file, _file_hash, _ct, _pi, _pk)
                else:
                    if _file_hash not in self.rpis[r]['hash']:
                        self.send_updates(r.title(), _name, _file, _file_hash, _ct, _pi, _pk)
                    else:
                        if self.rpis[r]['Status'] == "ERROR":
                            self.send_updates(r.title(), _name, _file, _file_hash, _ct, _pi, _pk)
                        else:
                            print(r.title() + ": Up to date for " + _name)

    def load_values(self):
        """
        Load previously saved values
        """
        dirname = os.path.dirname(__file__)
        if os.path.exists(dirname + '/' + self.nodes_filename):
            with open(dirname + '/' + self.nodes_filename, 'rb') as f:
                self.nodes = pickle.load(f)

        if os.path.exists(dirname + '/' + self.blockchain_filename):
            with open(dirname + '/' + self.blockchain_filename, 'rb') as f:
                self.chain = pickle.load(f)

        if os.path.exists(dirname + '/' + self.rpis_filename):
            with open(dirname + '/' + self.rpis_filename, 'rb') as f:
                self.rpis = pickle.load(f)

    def save_values(self):
        """
        Save values to files so we can close a node without losing information
        """
        dirname = os.path.dirname(__file__)
        with open(dirname + '/' + self.nodes_filename, 'wb') as f:
            pickle.dump(self.nodes, f, pickle.HIGHEST_PROTOCOL)

        with open(dirname + '/' + self.blockchain_filename, 'wb') as f:
            pickle.dump(self.chain, f, pickle.HIGHEST_PROTOCOL)

        with open(dirname + '/' + self.rpis_filename, 'wb') as f:
            pickle.dump(self.rpis, f, pickle.HIGHEST_PROTOCOL)

    def register_node(self, address):
        """
        Add a new node to the list of nodes
        :param address: Address of node. Eg. 'http://192.168.100.1:5000'
        """
        parsed_url = urlparse(address)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            # Accepts an URL without scheme like '192.168.100.1:5000'.
            self.nodes.add(parsed_url.path)
        else:
            messagebox.showerror("Register Node", "Invalid URL")
            return False
        return True

    def register_rpi(self, address):
        """
        Add a new RPi to the list of RPis
        :param address: Address of node. Eg. 'http://192.168.100.1:5000'
        """
        parsed_url = urlparse(address)
        if parsed_url.netloc:
            if not parsed_url.netloc in self.rpis:
                self.rpis[parsed_url.netloc] = {}
        elif parsed_url.path:
            # Accepts an URL without scheme like '192.168.100.1:5000'.
            #self.rpis.add(parsed_url.path)
            if not parsed_url.path in self.rpis:
                self.rpis[parsed_url.path] = {}
        else:
            messagebox.showerror("Register RPi", "Invalid URL")
            return False
        return True

    def valid_chain(self, chain): # Didn't use yet!

        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            print(f'{last_block}')
            print(f'{block}')
            print("\n-----------\n")
            # Check that the hash of the block is correct
            last_block_hash = self.hash(last_block)
            if block['previous_hash'] != last_block_hash:
                return False

            # Check that the Proof of Work is correct
            if not self.valid_proof(last_block['proof'], block['proof'], last_block_hash):
                return False

            last_block = block
            current_index += 1

        return True

    def resolve_conflicts(self):
        """
        This is our consensus algorithm, it resolves conflicts
        by replacing our chain with the longest one in the network.
        :return: True if our chain was replaced, False if not
        Other consensus can be used such as PBFT (https://github.com/LRAbbade/PBFT, https://github.com/luckydonald/pbft).
        """
        neighbours = self.nodes
        new_chain = None
        # We're only looking for chains longer than ours
        max_length = len(self.chain)

        # Grab and verify the chains from all the nodes in our network
        for node in neighbours:
            try:
                response = requests.get(f'http://{node}/chain')

                if response.status_code == 200:
                    length = response.json()['length']
                    chain = response.json()['chain']

                    # Check if the length is longer and the chain is valid
                    if length > max_length and self.valid_chain(chain):
                        max_length = length
                        new_chain = chain
            except requests.exceptions.Timeout as e:
                print("ERROR: Node " + node + " - Timeout " + str(e))
                return False
            except requests.exceptions.ConnectionError as ce:
                print("ERROR: Node " + node + " - Failed to establish connection")
                return False

        # Replace our chain if we discovered a new, valid chain longer than ours
        if new_chain:
            self.chain = new_chain
            return True

        return False

    def populate_block(self, block):

        for n in self.nodes:
            try:
                # Send as JSON with proper headers
                headers = {'Content-Type': 'application/json'}
                request = requests.post("http://" + n + "/blocks/new", json=block, headers=headers)
                print("Request Response Type: " + str(type(request.text)))
                print("Request Response: " + request.text[:200])  # Fixed: show first 200 chars, not from 200th
            except requests.exceptions.Timeout as e:
                print("ERROR: Node " + n + " - Timeout " + str(e))
                return False
            except requests.exceptions.ConnectionError as ce:
                print("ERROR: Node " + n + " - Failed to establish connection")
                return False

    def populate_transaction(self, transaction):
        if len(self.current_transactions) <= 0:
            return False

        for n in self.nodes:
            try:
                # Send as JSON with proper headers
                headers = {'Content-Type': 'application/json'}
                request = requests.post("http://" + n + "/transactions/new", json=transaction, headers=headers)
                print("Request Response Type: " + str(type(request.text)))
                print("Request Response: " + request.text[:200])  # Fixed: show first 200 chars, not from 200th
            except requests.exceptions.Timeout as e:
                print("ERROR: Node " + n + " - Timeout " + str(e))
                return False
            except requests.exceptions.ConnectionError as ce:
                print("ERROR: Node " + n + " - Failed to establish connection")
                return False

    def valid_file(self, transaction):
        if self._is_device_registration(transaction):
            return True  # No file to validate for device registration anchors

        _file = transaction['file']  # from where it's dictionary?
        _filename = transaction['name']

        # print('valid_file _file length ===>> ', len(_file))
        # print('valid_file input _file  ===>> ', _file)
        # print('_file Length is completely divisible by 4 (len%4),(len/4): ===>>', len(_file) % 4, len(_file) / 4)
        _file_bin = bytes(base64.b64decode(_file))

        # Check if File hash is equal to provided hash
        _hash = transaction['file_hash']
        _hash_verif = hashlib.sha256(_file_bin).hexdigest() # This is not ECDSA/Any signature verification
        if _hash != _hash_verif:
            messagebox.showerror("File Verification", "The Hash from File is different from provided hash")
            return 0
        return True

    def new_block(self, previous_hash, _transactions=None):
        # If there is no files to verify (transactions) and it is not the genesis block creation, exit
        if len(self.current_transactions) <= 0 and previous_hash != '1':
            if _transactions is None:
                return False

        if previous_hash != '1':
            if _transactions is None:  #if origin is local mining
                for transaction in self.current_transactions:
                    if self.valid_file(transaction) == False:
                        return False
            else:
                for transaction in _transactions: #if origin is external block
                    if self.valid_file(transaction) == False:
                        return False
        if len(self.chain) > 0:
            print(self.chain[-1])
            previous_hash = self.chain[-1]['hash']

        block = {
            'index': len(self.chain) + 1,
            'timestamp': time.time(), #time is not coming as a right
            'transactions': self.current_transactions,
            'previous_hash': previous_hash or self.hash(self.chain[-1])
        }
        block['hash'] = self.hash(block) # block hash korte na parle? Separately test korbo!
        # Reset the current list of transactions
        self.current_transactions = []

        self.chain.append(block)
        print("INFO - Added block " + str(block['index']) + " with hash: " + block['hash'])
        #self.resolve_conflicts()

        return block

    def new_transaction(self, name, file, file_hash, ct, pi, pk):
        transaction = {
            'type': 'message',
            'name': name,
            'file': file,
            'file_hash': file_hash,
            'ct': ct,
            'pi': pi,
            'pk': pk
        }
        self.current_transactions.append(transaction)

        # we send this transaction over the nodes network
        self.populate_transaction(transaction)

        return self.last_block['index'] + 1

    def new_transaction_device_registration(self, did_i, vc_hash, timestamp=None):
        """Phase 1: Anchor device registration on chain. Blockchain adds {did_i, vc_hash, timestamp}."""
        if timestamp is None:
            timestamp = time.time()
        transaction = {
            'type': 'device_registration',
            'did_i': did_i,
            'vc_hash': vc_hash,
            'timestamp': timestamp
        }
        self.current_transactions.append(transaction)
        self.populate_transaction(transaction)
        return self.last_block['index'] + 1

    @property
    def last_block(self):
        print("Chain Len: " + str(len(self.chain)))
        return self.chain[-1]

# Tough things here, need to check every where, hash thing!
    @staticmethod
    def hash(block):
        """
        Creates a SHA-256 hash of a Block.
        For blocks with device_registration anchors use full block JSON; else legacy (first tx ct).
        """
        trns_list = block['transactions']

        if len(trns_list) > 0:
            first = trns_list[0]
            if first.get('type') == 'device_registration':
                # Phase 1: canonical hash of full block for anchor blocks
                block_string = json.dumps(block, sort_keys=True).encode()
                return hashlib.sha256(block_string).hexdigest()
            # Legacy: first transaction's ct (message type)
            if 'ct' in first:
                print("Block ==> " + str(block))
                block_string = json.dumps(first['ct'], sort_keys=True).encode()
                return hashlib.sha256(block_string).hexdigest()
            block_string = json.dumps(block, sort_keys=True).encode()
            return hashlib.sha256(block_string).hexdigest()
        else:
            print("Block ==> " + str(block))
            block_string = json.dumps(block, sort_keys=True).encode()
            return hashlib.sha256(block_string).hexdigest()

    @staticmethod
    def valid_proof(last_proof, proof, last_hash):
        guess = f'{last_proof}{proof}{last_hash}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"