"""
EscrowPay RPC Test - On-chain Escrow & Payment System

Tests the full flow:
1. Create accounts in keystore
2. Fund accounts via faucet
3. Create escrow (buyer locks funds for seller)
4. Release escrow (buyer sends funds to seller)
5. Create another escrow and refund it
6. Query final account states

Run with: python escrowpay_test.py
"""

import os, sys, time, json, secrets, base64
from dataclasses import dataclass
import urllib.request, urllib.error

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'proto'))

from google.protobuf import any_pb2
import tx_pb2
from blspy import PrivateKey, BasicSchemeMPL

QUERY_RPC_URL = "http://localhost:50002"
ADMIN_RPC_URL = "http://localhost:50003"
NETWORK_ID = 1
CHAIN_ID = 1
TEST_PASSWORD = "testpassword123"


@dataclass
class KeyGroup:
    address: str
    public_key: str
    private_key: str

def random_suffix(): return secrets.token_hex(4)
def hex_to_base64(h): return base64.b64encode(bytes.fromhex(h)).decode()
def hex_to_bytes(h): return bytes.fromhex(h)
def bytes_to_hex(b): return b.hex()

def post_raw_json(url, json_body):
    req = urllib.request.Request(url, data=json_body.encode(), headers={'Content-Type': 'application/json'}, method='POST')
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.read().decode()
    except urllib.error.HTTPError as e:
        raise Exception(f"HTTP {e.code}: {e.read().decode() if e.fp else str(e)}")

def keystore_new_key(rpc_url, nickname, password):
    return json.loads(post_raw_json(f"{rpc_url}/v1/admin/keystore-new-key", json.dumps({"nickname": nickname, "password": password})))

def keystore_get_key(rpc_url, address, password):
    p = json.loads(post_raw_json(f"{rpc_url}/v1/admin/keystore-get", json.dumps({"address": address, "password": password})))
    return KeyGroup(p.get('address', address), p.get('publicKey') or p.get('public_key'), p.get('privateKey') or p.get('private_key'))

def get_height(rpc_url):
    return json.loads(post_raw_json(f"{rpc_url}/v1/query/height", "{}")).get('height', 0)

def get_account(rpc_url, address):
    return json.loads(post_raw_json(f"{rpc_url}/v1/query/account", json.dumps({"address": address})))

def sign_bls(pk_hex, message):
    return bytes(BasicSchemeMPL.sign(PrivateKey.from_bytes(hex_to_bytes(pk_hex)), message))

def build_sign_and_send_tx(rpc_url, signer_key, msg_type, msg_type_url, msg_bytes, fee, nid, cid, height):
    tx_time = int(time.time() * 1_000_000)
    any_msg = any_pb2.Any(); any_msg.type_url = msg_type_url; any_msg.value = msg_bytes
    tx = tx_pb2.Transaction(); tx.message_type = msg_type; tx.msg.CopyFrom(any_msg)
    tx.created_height = height; tx.time = tx_time; tx.fee = fee; tx.network_id = nid; tx.chain_id = cid
    sig = sign_bls(signer_key.private_key, tx.SerializeToString())
    tx_json = {'type': msg_type, 'msgTypeUrl': msg_type_url, 'msgBytes': bytes_to_hex(msg_bytes),
               'signature': {'publicKey': bytes_to_hex(hex_to_bytes(signer_key.public_key)), 'signature': bytes_to_hex(sig)},
               'time': tx_time, 'createdHeight': height, 'fee': fee, 'memo': '', 'networkID': nid, 'chainID': cid}
    if msg_type == 'send':
        tx_json.pop('msgTypeUrl'); tx_json.pop('msgBytes')
        sm = tx_pb2.MessageSend(); sm.ParseFromString(msg_bytes)
        tx_json['msg'] = {'fromAddress': hex_to_base64(bytes_to_hex(sm.from_address)), 'toAddress': hex_to_base64(bytes_to_hex(sm.to_address)), 'amount': sm.amount}
    return json.loads(post_raw_json(f"{rpc_url}/v1/tx", json.dumps(tx_json)))

def send_faucet(rpc, key, addr, amt, fee, nid, cid, h):
    m = tx_pb2.MessageFaucet(); m.signer_address = hex_to_bytes(key.address); m.recipient_address = hex_to_bytes(addr); m.amount = amt
    return build_sign_and_send_tx(rpc, key, 'faucet', 'type.googleapis.com/types.MessageFaucet', m.SerializeToString(), fee, nid, cid, h)

def send_create_escrow(rpc, buyer_key, seller_addr, amount, desc, timeout, fee, nid, cid, h):
    m = tx_pb2.MessageCreateEscrow(); m.buyer = hex_to_bytes(buyer_key.address); m.seller = hex_to_bytes(seller_addr)
    m.amount = amount; m.description = desc; m.timeout_height = timeout
    return build_sign_and_send_tx(rpc, buyer_key, 'create_escrow', 'type.googleapis.com/types.MessageCreateEscrow', m.SerializeToString(), fee, nid, cid, h)

def send_release(rpc, buyer_key, escrow_id, fee, nid, cid, h):
    m = tx_pb2.MessageRelease(); m.buyer = hex_to_bytes(buyer_key.address); m.escrow_id = escrow_id
    return build_sign_and_send_tx(rpc, buyer_key, 'release', 'type.googleapis.com/types.MessageRelease', m.SerializeToString(), fee, nid, cid, h)

def send_refund(rpc, buyer_key, escrow_id, fee, nid, cid, h):
    m = tx_pb2.MessageRefund(); m.claimer = hex_to_bytes(buyer_key.address); m.escrow_id = escrow_id
    return build_sign_and_send_tx(rpc, buyer_key, 'refund', 'type.googleapis.com/types.MessageRefund', m.SerializeToString(), fee, nid, cid, h)


def test_escrowpay():
    print("=" * 60)
    print("  EscrowPay - On-chain Escrow & Payment System")
    print("=" * 60)

    suffix = random_suffix()
    fee = 10000

    # Step 1: Create accounts
    print("\n[Step 1] Creating accounts...")
    buyer1_addr = keystore_new_key(ADMIN_RPC_URL, f"buyer1_{suffix}", TEST_PASSWORD)
    seller1_addr = keystore_new_key(ADMIN_RPC_URL, f"seller1_{suffix}", TEST_PASSWORD)
    buyer2_addr = keystore_new_key(ADMIN_RPC_URL, f"buyer2_{suffix}", TEST_PASSWORD)
    seller2_addr = keystore_new_key(ADMIN_RPC_URL, f"seller2_{suffix}", TEST_PASSWORD)
    print(f"  Buyer1:  {buyer1_addr}")
    print(f"  Seller1: {seller1_addr}")
    print(f"  Buyer2:  {buyer2_addr}")
    print(f"  Seller2: {seller2_addr}")

    buyer1_key = keystore_get_key(ADMIN_RPC_URL, buyer1_addr, TEST_PASSWORD)
    seller1_key = keystore_get_key(ADMIN_RPC_URL, seller1_addr, TEST_PASSWORD)
    buyer2_key = keystore_get_key(ADMIN_RPC_URL, buyer2_addr, TEST_PASSWORD)
    seller2_key = keystore_get_key(ADMIN_RPC_URL, seller2_addr, TEST_PASSWORD)

    # Step 2: Fund accounts
    print("\n[Step 2] Funding accounts via faucet...")
    height = get_height(QUERY_RPC_URL)
    for name, key, addr in [("Buyer1", buyer1_key, buyer1_addr), ("Seller1", seller1_key, seller1_addr), ("Buyer2", buyer2_key, buyer2_addr), ("Seller2", seller2_key, seller2_addr)]:
        send_faucet(QUERY_RPC_URL, key, addr, 2000000000, fee, NETWORK_ID, CHAIN_ID, height)
        print(f"  {name} funded")
        time.sleep(2)
    time.sleep(3)

    # Step 3: Create escrow #1 (Buyer1 -> Seller1, 100M uCNPY for NFT)
    print("\n[Step 3] Creating escrow #1 (NFT purchase)...")
    height = get_height(QUERY_RPC_URL)
    tx = send_create_escrow(QUERY_RPC_URL, buyer1_key, seller1_addr, 100000000, "NFT purchase #5678", height + 50000, fee, NETWORK_ID, CHAIN_ID, height)
    print(f"  Escrow #1 created: {tx}")
    time.sleep(3)

    # Step 4: Release escrow #1 (Buyer1 confirms delivery, funds go to Seller1)
    print("\n[Step 4] Releasing escrow #1 (delivery confirmed)...")
    height = get_height(QUERY_RPC_URL)
    tx = send_release(QUERY_RPC_URL, buyer1_key, 1, fee, NETWORK_ID, CHAIN_ID, height)
    print(f"  Escrow #1 released: {tx}")
    time.sleep(3)

    # Step 5: Create escrow #2 (Buyer2 -> Seller2, 50M uCNPY for service)
    print("\n[Step 5] Creating escrow #2 (freelance service)...")
    height = get_height(QUERY_RPC_URL)
    tx = send_create_escrow(QUERY_RPC_URL, buyer2_key, seller2_addr, 50000000, "Smart contract audit service", height + 30000, fee, NETWORK_ID, CHAIN_ID, height)
    print(f"  Escrow #2 created: {tx}")
    time.sleep(3)

    # Step 6: Refund escrow #2 (Buyer2 cancels, gets money back)
    print("\n[Step 6] Refunding escrow #2 (service cancelled)...")
    height = get_height(QUERY_RPC_URL)
    tx = send_refund(QUERY_RPC_URL, buyer2_key, 2, fee, NETWORK_ID, CHAIN_ID, height)
    print(f"  Escrow #2 refunded: {tx}")
    time.sleep(3)

    # Step 7: Final account states
    print("\n[Step 7] Final account states:")
    print("-" * 60)
    for name, addr in [("Buyer1 (released)", buyer1_addr), ("Seller1 (received)", seller1_addr), ("Buyer2 (refunded)", buyer2_addr), ("Seller2 (no payment)", seller2_addr)]:
        acct = get_account(QUERY_RPC_URL, addr)
        amount = acct.get('amount', 0)
        created = acct.get('escrowsCreated', 0)
        released = acct.get('escrowsReleased', 0)
        received = acct.get('escrowsReceived', 0)
        print(f"  {name}:")
        print(f"    Balance:          {amount}")
        print(f"    Escrows Created:  {created}")
        print(f"    Escrows Released: {released}")
        print(f"    Payments Received: {received}")

    print("\n" + "=" * 60)
    print("  EscrowPay test completed!")
    print("=" * 60)
    print("\n  Summary:")
    print("  Escrow #1: Buyer1 locked 100M -> released to Seller1 (NFT delivered)")
    print("  Escrow #2: Buyer2 locked 50M -> refunded to Buyer2 (service cancelled)")


if __name__ == "__main__":
    try:
        test_escrowpay()
    except Exception as e:
        print(f"\nTest failed: {e}")
        import traceback; traceback.print_exc()
        sys.exit(1)
