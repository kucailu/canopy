"""
EscrowPay - On-chain Escrow & Payment Plugin for Canopy Network

Custom transaction types:
- send: standard token transfer
- create_escrow: create an escrow contract (buyer locks funds for seller)
- release: buyer releases escrowed funds to seller
- refund: buyer reclaims escrowed funds after timeout

State key prefixes:
- 0x01: Account
- 0x02: Pool
- 0x03: Escrow
- 0x05: EscrowCounter
- 0x07: Params
"""

import random
import struct
from typing import Optional, Any, Union, TYPE_CHECKING

if TYPE_CHECKING:
    from .plugin import Plugin, Config

from .proto import (
    PluginCheckRequest,
    PluginCheckResponse,
    PluginDeliverRequest,
    PluginDeliverResponse,
    PluginGenesisRequest,
    PluginGenesisResponse,
    PluginBeginRequest,
    PluginBeginResponse,
    PluginEndRequest,
    PluginEndResponse,
    MessageSend,
    MessageCreateEscrow,
    MessageRelease,
    MessageRefund,
    PluginKeyRead,
    PluginStateReadRequest,
    PluginStateWriteRequest,
    PluginSetOp,
    PluginDeleteOp,
    PluginFSMConfig,
    FeeParams,
    Account,
    Pool,
    Escrow,
)
from .proto import account_pb2, event_pb2, plugin_pb2, tx_pb2
from google.protobuf import any_pb2

from .error import (
    PluginError,
    err_invalid_address,
    err_invalid_amount,
    err_insufficient_funds,
    err_tx_fee_below_state_limit,
    err_invalid_message_cast,
    err_unmarshal,
)

# Plugin configuration
CONTRACT_CONFIG = {
    "name": "escrowpay_escrow_system",
    "id": 1,
    "version": 1,
    "supported_transactions": ["send", "create_escrow", "release", "refund"],
    "transaction_type_urls": [
        "type.googleapis.com/types.MessageSend",
        "type.googleapis.com/types.MessageCreateEscrow",
        "type.googleapis.com/types.MessageRelease",
        "type.googleapis.com/types.MessageRefund",
    ],
    "event_type_urls": [],
    "file_descriptor_protos": [
        any_pb2.DESCRIPTOR.serialized_pb,
        account_pb2.DESCRIPTOR.serialized_pb,
        event_pb2.DESCRIPTOR.serialized_pb,
        plugin_pb2.DESCRIPTOR.serialized_pb,
        tx_pb2.DESCRIPTOR.serialized_pb,
    ],
}

# State key prefixes
ACCOUNT_PREFIX = b"\x01"
POOL_PREFIX = b"\x02"
ESCROW_PREFIX = b"\x03"
ESCROW_COUNTER_KEY = b"\x05\x00"
PARAMS_PREFIX = b"\x07"

# Escrow status
STATUS_ACTIVE = 0
STATUS_RELEASED = 1
STATUS_REFUNDED = 2


def join_len_prefix(*items: Optional[bytes]) -> bytes:
    result = bytearray()
    for item in items:
        if not item:
            continue
        if len(item) > 255:
            raise ValueError(f"Item too long: {len(item)} bytes (max 255)")
        result.append(len(item))
        result.extend(item)
    return bytes(result)


def format_uint64(value: Union[int, str]) -> bytes:
    if isinstance(value, str):
        value = int(value)
    if not isinstance(value, int) or value < 0 or value >= (1 << 64):
        raise ValueError(f"Invalid uint64 value: {value}")
    return struct.pack('>Q', value)


def key_for_account(address: bytes) -> bytes:
    return join_len_prefix(ACCOUNT_PREFIX, address)


def key_for_fee_params() -> bytes:
    return join_len_prefix(PARAMS_PREFIX, b"/f/")


def key_for_fee_pool(chain_id: int) -> bytes:
    return join_len_prefix(POOL_PREFIX, format_uint64(chain_id))


def key_for_escrow(escrow_id: int) -> bytes:
    return join_len_prefix(ESCROW_PREFIX, format_uint64(escrow_id))


def marshal(message: Any) -> bytes:
    try:
        if hasattr(message, 'SerializeToString'):
            return message.SerializeToString()
        raise ValueError("Message does not support serialization")
    except Exception as err:
        raise err_unmarshal(err)


def unmarshal(message_type: Any, data: Optional[bytes]) -> Optional[Any]:
    if not data:
        return None
    try:
        if hasattr(message_type, 'FromString'):
            return message_type.FromString(data)
        raise ValueError("Message type does not support deserialization")
    except Exception as err:
        raise err_unmarshal(err)


# Custom errors
def err_escrow_not_found() -> PluginError:
    return PluginError(10, "escrow", "Escrow not found")

def err_escrow_not_active() -> PluginError:
    return PluginError(11, "escrow", "Escrow is not active")

def err_not_buyer() -> PluginError:
    return PluginError(12, "escrow", "Only the buyer can perform this action")

def err_timeout_not_reached() -> PluginError:
    return PluginError(13, "escrow", "Escrow timeout has not been reached yet")

def err_same_address() -> PluginError:
    return PluginError(14, "escrow", "Buyer and seller cannot be the same address")

def err_invalid_description() -> PluginError:
    return PluginError(15, "escrow", "Description must be 5-200 characters")

def err_invalid_timeout() -> PluginError:
    return PluginError(16, "escrow", "Timeout height must be in the future")


class Contract:
    """EscrowPay - On-chain Escrow & Payment Contract"""

    def __init__(
        self,
        config: Optional["Config"] = None,
        fsm_config: Optional[PluginFSMConfig] = None,
        plugin: Optional["Plugin"] = None,
        fsm_id: Optional[int] = None,
    ):
        self.config = config
        self.fsm_config = fsm_config
        self.plugin = plugin
        self.fsm_id = fsm_id

    def genesis(self, request: PluginGenesisRequest) -> PluginGenesisResponse:
        return PluginGenesisResponse()

    def begin_block(self, request: PluginBeginRequest) -> PluginBeginResponse:
        return PluginBeginResponse()

    async def check_tx(self, request: PluginCheckRequest) -> PluginCheckResponse:
        try:
            if not self.plugin or not self.config:
                raise PluginError(1, "plugin", "plugin or config not initialized")

            resp = await self.plugin.state_read(
                self,
                PluginStateReadRequest(
                    keys=[PluginKeyRead(query_id=random.randint(0, 2**53), key=key_for_fee_params())]
                ),
            )

            if resp.HasField("error"):
                response = PluginCheckResponse()
                response.error.CopyFrom(resp.error)
                return response

            if not resp.results or not resp.results[0].entries:
                raise PluginError(1, "plugin", "Fee parameters not found")

            fee_params_bytes = resp.results[0].entries[0].value
            min_fees = unmarshal(FeeParams, fee_params_bytes)
            if not min_fees:
                raise PluginError(1, "plugin", "Failed to decode fee parameters")

            type_url = request.tx.msg.type_url

            if type_url.endswith("/types.MessageSend"):
                if request.tx.fee < min_fees.send_fee:
                    raise err_tx_fee_below_state_limit()
                msg = MessageSend()
                msg.ParseFromString(request.tx.msg.value)
                return self._check_message_send(msg)

            elif type_url.endswith("/types.MessageCreateEscrow"):
                if request.tx.fee < min_fees.create_escrow_fee:
                    raise err_tx_fee_below_state_limit()
                msg = MessageCreateEscrow()
                msg.ParseFromString(request.tx.msg.value)
                return self._check_message_create_escrow(msg)

            elif type_url.endswith("/types.MessageRelease"):
                if request.tx.fee < min_fees.release_fee:
                    raise err_tx_fee_below_state_limit()
                msg = MessageRelease()
                msg.ParseFromString(request.tx.msg.value)
                return self._check_message_release(msg)

            elif type_url.endswith("/types.MessageRefund"):
                if request.tx.fee < min_fees.refund_fee:
                    raise err_tx_fee_below_state_limit()
                msg = MessageRefund()
                msg.ParseFromString(request.tx.msg.value)
                return self._check_message_refund(msg)

            else:
                raise err_invalid_message_cast()

        except PluginError as e:
            response = PluginCheckResponse()
            response.error.code = e.code
            response.error.module = e.module
            response.error.msg = e.msg
            return response
        except Exception as err:
            response = PluginCheckResponse()
            response.error.code = 1
            response.error.module = "plugin"
            response.error.msg = str(err)
            return response

    async def deliver_tx(self, request: PluginDeliverRequest) -> PluginDeliverResponse:
        try:
            type_url = request.tx.msg.type_url

            if type_url.endswith("/types.MessageSend"):
                msg = MessageSend()
                msg.ParseFromString(request.tx.msg.value)
                return await self._deliver_message_send(msg, request.tx.fee)

            elif type_url.endswith("/types.MessageCreateEscrow"):
                msg = MessageCreateEscrow()
                msg.ParseFromString(request.tx.msg.value)
                return await self._deliver_message_create_escrow(msg, request.tx.fee)

            elif type_url.endswith("/types.MessageRelease"):
                msg = MessageRelease()
                msg.ParseFromString(request.tx.msg.value)
                return await self._deliver_message_release(msg, request.tx.fee)

            elif type_url.endswith("/types.MessageRefund"):
                msg = MessageRefund()
                msg.ParseFromString(request.tx.msg.value)
                return await self._deliver_message_refund(msg, request.tx.fee)

            else:
                raise err_invalid_message_cast()

        except PluginError as e:
            response = PluginDeliverResponse()
            response.error.code = e.code
            response.error.module = e.module
            response.error.msg = e.msg
            return response
        except Exception as err:
            response = PluginDeliverResponse()
            response.error.code = 1
            response.error.module = "plugin"
            response.error.msg = str(err)
            return response

    def end_block(self, request: PluginEndRequest) -> PluginEndResponse:
        return PluginEndResponse()

    # ===== CHECK =====

    def _check_message_send(self, msg: MessageSend) -> PluginCheckResponse:
        if len(msg.from_address) != 20:
            raise err_invalid_address()
        if len(msg.to_address) != 20:
            raise err_invalid_address()
        if msg.amount == 0:
            raise err_invalid_amount()
        response = PluginCheckResponse()
        response.recipient = msg.to_address
        response.authorized_signers.append(msg.from_address)
        return response

    def _check_message_create_escrow(self, msg: MessageCreateEscrow) -> PluginCheckResponse:
        if len(msg.buyer) != 20:
            raise err_invalid_address()
        if len(msg.seller) != 20:
            raise err_invalid_address()
        if msg.buyer == msg.seller:
            raise err_same_address()
        if msg.amount == 0:
            raise err_invalid_amount()
        if len(msg.description) < 5 or len(msg.description) > 200:
            raise err_invalid_description()
        if msg.timeout_height == 0:
            raise err_invalid_timeout()
        response = PluginCheckResponse()
        response.authorized_signers.append(msg.buyer)
        return response

    def _check_message_release(self, msg: MessageRelease) -> PluginCheckResponse:
        if len(msg.buyer) != 20:
            raise err_invalid_address()
        if msg.escrow_id == 0:
            raise err_escrow_not_found()
        response = PluginCheckResponse()
        response.authorized_signers.append(msg.buyer)
        return response

    def _check_message_refund(self, msg: MessageRefund) -> PluginCheckResponse:
        if len(msg.claimer) != 20:
            raise err_invalid_address()
        if msg.escrow_id == 0:
            raise err_escrow_not_found()
        response = PluginCheckResponse()
        response.authorized_signers.append(msg.claimer)
        return response

    # ===== DELIVER =====

    async def _deliver_message_send(self, msg: MessageSend, fee: int) -> PluginDeliverResponse:
        if not self.plugin or not self.config:
            raise PluginError(1, "plugin", "plugin or config not initialized")

        from_qid = random.randint(0, 2**53)
        to_qid = random.randint(0, 2**53)
        fee_qid = random.randint(0, 2**53)

        from_key = key_for_account(msg.from_address)
        to_key = key_for_account(msg.to_address)
        fee_pool_key = key_for_fee_pool(self.config.chain_id)

        response = await self.plugin.state_read(
            self,
            PluginStateReadRequest(
                keys=[
                    PluginKeyRead(query_id=fee_qid, key=fee_pool_key),
                    PluginKeyRead(query_id=from_qid, key=from_key),
                    PluginKeyRead(query_id=to_qid, key=to_key),
                ]
            ),
        )

        if response.HasField("error"):
            result = PluginDeliverResponse()
            result.error.CopyFrom(response.error)
            return result

        from_bytes = to_bytes = fee_pool_bytes = None
        for resp in response.results:
            if resp.query_id == from_qid:
                from_bytes = resp.entries[0].value if resp.entries else None
            elif resp.query_id == to_qid:
                to_bytes = resp.entries[0].value if resp.entries else None
            elif resp.query_id == fee_qid:
                fee_pool_bytes = resp.entries[0].value if resp.entries else None

        amount_to_deduct = msg.amount + fee
        from_account = unmarshal(Account, from_bytes) if from_bytes else Account()
        to_account = unmarshal(Account, to_bytes) if to_bytes else Account()
        fee_pool = unmarshal(Pool, fee_pool_bytes) if fee_pool_bytes else Pool()

        if from_account.amount < amount_to_deduct:
            raise err_insufficient_funds()

        if from_key == to_key:
            to_account = from_account

        from_account.amount -= amount_to_deduct
        fee_pool.amount += fee
        to_account.amount += msg.amount

        if from_account.amount == 0:
            write_resp = await self.plugin.state_write(
                self,
                PluginStateWriteRequest(
                    sets=[
                        PluginSetOp(key=fee_pool_key, value=marshal(fee_pool)),
                        PluginSetOp(key=to_key, value=marshal(to_account)),
                    ],
                    deletes=[PluginDeleteOp(key=from_key)],
                ),
            )
        else:
            write_resp = await self.plugin.state_write(
                self,
                PluginStateWriteRequest(
                    sets=[
                        PluginSetOp(key=fee_pool_key, value=marshal(fee_pool)),
                        PluginSetOp(key=to_key, value=marshal(to_account)),
                        PluginSetOp(key=from_key, value=marshal(from_account)),
                    ],
                ),
            )

        result = PluginDeliverResponse()
        if write_resp.HasField("error"):
            result.error.CopyFrom(write_resp.error)
        return result

    async def _deliver_message_create_escrow(self, msg: MessageCreateEscrow, fee: int) -> PluginDeliverResponse:
        """Create a new escrow contract: lock buyer's funds until release or refund."""
        if not self.plugin or not self.config:
            raise PluginError(1, "plugin", "plugin or config not initialized")

        counter_qid = random.randint(0, 2**53)
        buyer_qid = random.randint(0, 2**53)
        fee_qid = random.randint(0, 2**53)

        buyer_key = key_for_account(msg.buyer)
        fee_pool_key = key_for_fee_pool(self.config.chain_id)

        response = await self.plugin.state_read(
            self,
            PluginStateReadRequest(
                keys=[
                    PluginKeyRead(query_id=counter_qid, key=ESCROW_COUNTER_KEY),
                    PluginKeyRead(query_id=buyer_qid, key=buyer_key),
                    PluginKeyRead(query_id=fee_qid, key=fee_pool_key),
                ]
            ),
        )

        if response.HasField("error"):
            result = PluginDeliverResponse()
            result.error.CopyFrom(response.error)
            return result

        counter_bytes = buyer_bytes = fee_pool_bytes = None
        for resp in response.results:
            if resp.query_id == counter_qid:
                counter_bytes = resp.entries[0].value if resp.entries else None
            elif resp.query_id == buyer_qid:
                buyer_bytes = resp.entries[0].value if resp.entries else None
            elif resp.query_id == fee_qid:
                fee_pool_bytes = resp.entries[0].value if resp.entries else None

        # Parse counter
        if counter_bytes and len(counter_bytes) >= 8:
            escrow_id = struct.unpack('>Q', counter_bytes[:8])[0] + 1
        else:
            escrow_id = 1

        buyer_account = unmarshal(Account, buyer_bytes) if buyer_bytes else Account()
        fee_pool = unmarshal(Pool, fee_pool_bytes) if fee_pool_bytes else Pool()

        # Deduct escrow amount + fee from buyer
        total_deduct = msg.amount + fee
        if buyer_account.amount < total_deduct:
            raise err_insufficient_funds()

        buyer_account.amount -= total_deduct
        fee_pool.amount += fee
        buyer_account.escrows_created += 1

        # Create escrow record
        escrow = Escrow()
        escrow.id = escrow_id
        escrow.buyer = msg.buyer
        escrow.seller = msg.seller
        escrow.amount = msg.amount
        escrow.description = msg.description
        escrow.timeout_height = msg.timeout_height
        escrow.status = STATUS_ACTIVE
        escrow.created_height = 0  # will be set by block context if available

        write_resp = await self.plugin.state_write(
            self,
            PluginStateWriteRequest(
                sets=[
                    PluginSetOp(key=ESCROW_COUNTER_KEY, value=format_uint64(escrow_id)),
                    PluginSetOp(key=buyer_key, value=marshal(buyer_account)),
                    PluginSetOp(key=fee_pool_key, value=marshal(fee_pool)),
                    PluginSetOp(key=key_for_escrow(escrow_id), value=marshal(escrow)),
                ],
            ),
        )

        result = PluginDeliverResponse()
        if write_resp.HasField("error"):
            result.error.CopyFrom(write_resp.error)
        return result

    async def _deliver_message_release(self, msg: MessageRelease, fee: int) -> PluginDeliverResponse:
        """Release escrowed funds to the seller (buyer authorizes)."""
        if not self.plugin or not self.config:
            raise PluginError(1, "plugin", "plugin or config not initialized")

        escrow_qid = random.randint(0, 2**53)
        buyer_qid = random.randint(0, 2**53)
        seller_qid = random.randint(0, 2**53)
        fee_qid = random.randint(0, 2**53)

        escrow_key = key_for_escrow(msg.escrow_id)
        fee_pool_key = key_for_fee_pool(self.config.chain_id)

        response = await self.plugin.state_read(
            self,
            PluginStateReadRequest(
                keys=[
                    PluginKeyRead(query_id=escrow_qid, key=escrow_key),
                    PluginKeyRead(query_id=fee_qid, key=fee_pool_key),
                ]
            ),
        )

        if response.HasField("error"):
            result = PluginDeliverResponse()
            result.error.CopyFrom(response.error)
            return result

        escrow_bytes = fee_pool_bytes = None
        for resp in response.results:
            if resp.query_id == escrow_qid:
                escrow_bytes = resp.entries[0].value if resp.entries else None
            elif resp.query_id == fee_qid:
                fee_pool_bytes = resp.entries[0].value if resp.entries else None

        # Validate escrow
        escrow = unmarshal(Escrow, escrow_bytes)
        if not escrow or not escrow.id:
            raise err_escrow_not_found()
        if escrow.status != STATUS_ACTIVE:
            raise err_escrow_not_active()
        if escrow.buyer != msg.buyer:
            raise err_not_buyer()

        fee_pool = unmarshal(Pool, fee_pool_bytes) if fee_pool_bytes else Pool()

        # Now read buyer and seller accounts
        buyer_key = key_for_account(escrow.buyer)
        seller_key = key_for_account(escrow.seller)
        buyer_qid2 = random.randint(0, 2**53)
        seller_qid2 = random.randint(0, 2**53)

        acct_resp = await self.plugin.state_read(
            self,
            PluginStateReadRequest(
                keys=[
                    PluginKeyRead(query_id=buyer_qid2, key=buyer_key),
                    PluginKeyRead(query_id=seller_qid2, key=seller_key),
                ]
            ),
        )

        buyer_bytes = seller_bytes = None
        for resp in acct_resp.results:
            if resp.query_id == buyer_qid2:
                buyer_bytes = resp.entries[0].value if resp.entries else None
            elif resp.query_id == seller_qid2:
                seller_bytes = resp.entries[0].value if resp.entries else None

        buyer_account = unmarshal(Account, buyer_bytes) if buyer_bytes else Account()
        seller_account = unmarshal(Account, seller_bytes) if seller_bytes else Account()

        # Deduct fee from buyer
        if buyer_account.amount < fee:
            raise err_insufficient_funds()

        buyer_account.amount -= fee
        fee_pool.amount += fee

        # Release escrow amount to seller
        seller_account.amount += escrow.amount
        seller_account.escrows_received += 1

        # Update buyer counter
        buyer_account.escrows_released += 1

        # Mark escrow as released
        escrow.status = STATUS_RELEASED

        write_resp = await self.plugin.state_write(
            self,
            PluginStateWriteRequest(
                sets=[
                    PluginSetOp(key=escrow_key, value=marshal(escrow)),
                    PluginSetOp(key=buyer_key, value=marshal(buyer_account)),
                    PluginSetOp(key=seller_key, value=marshal(seller_account)),
                    PluginSetOp(key=fee_pool_key, value=marshal(fee_pool)),
                ],
            ),
        )

        result = PluginDeliverResponse()
        if write_resp.HasField("error"):
            result.error.CopyFrom(write_resp.error)
        return result

    async def _deliver_message_refund(self, msg: MessageRefund, fee: int) -> PluginDeliverResponse:
        """Refund escrowed funds to the buyer (after timeout or by buyer)."""
        if not self.plugin or not self.config:
            raise PluginError(1, "plugin", "plugin or config not initialized")

        escrow_qid = random.randint(0, 2**53)
        fee_qid = random.randint(0, 2**53)

        escrow_key = key_for_escrow(msg.escrow_id)
        fee_pool_key = key_for_fee_pool(self.config.chain_id)

        response = await self.plugin.state_read(
            self,
            PluginStateReadRequest(
                keys=[
                    PluginKeyRead(query_id=escrow_qid, key=escrow_key),
                    PluginKeyRead(query_id=fee_qid, key=fee_pool_key),
                ]
            ),
        )

        if response.HasField("error"):
            result = PluginDeliverResponse()
            result.error.CopyFrom(response.error)
            return result

        escrow_bytes = fee_pool_bytes = None
        for resp in response.results:
            if resp.query_id == escrow_qid:
                escrow_bytes = resp.entries[0].value if resp.entries else None
            elif resp.query_id == fee_qid:
                fee_pool_bytes = resp.entries[0].value if resp.entries else None

        # Validate escrow
        escrow = unmarshal(Escrow, escrow_bytes)
        if not escrow or not escrow.id:
            raise err_escrow_not_found()
        if escrow.status != STATUS_ACTIVE:
            raise err_escrow_not_active()
        if escrow.buyer != msg.claimer:
            raise err_not_buyer()

        fee_pool = unmarshal(Pool, fee_pool_bytes) if fee_pool_bytes else Pool()

        # Read buyer account
        buyer_key = key_for_account(escrow.buyer)
        buyer_qid2 = random.randint(0, 2**53)

        acct_resp = await self.plugin.state_read(
            self,
            PluginStateReadRequest(
                keys=[PluginKeyRead(query_id=buyer_qid2, key=buyer_key)]
            ),
        )

        buyer_bytes = None
        for resp in acct_resp.results:
            if resp.query_id == buyer_qid2:
                buyer_bytes = resp.entries[0].value if resp.entries else None

        buyer_account = unmarshal(Account, buyer_bytes) if buyer_bytes else Account()

        # Deduct fee from buyer
        if buyer_account.amount < fee:
            raise err_insufficient_funds()

        buyer_account.amount -= fee
        fee_pool.amount += fee

        # Refund escrow amount to buyer
        buyer_account.amount += escrow.amount

        # Mark escrow as refunded
        escrow.status = STATUS_REFUNDED

        write_resp = await self.plugin.state_write(
            self,
            PluginStateWriteRequest(
                sets=[
                    PluginSetOp(key=escrow_key, value=marshal(escrow)),
                    PluginSetOp(key=buyer_key, value=marshal(buyer_account)),
                    PluginSetOp(key=fee_pool_key, value=marshal(fee_pool)),
                ],
            ),
        )

        result = PluginDeliverResponse()
        if write_resp.HasField("error"):
            result.error.CopyFrom(write_resp.error)
        return result
