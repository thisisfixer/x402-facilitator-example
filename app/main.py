import time
import logging

from eth_account import Account
from eth_account.messages import encode_typed_data
from fastapi import FastAPI
from web3 import Web3
from app.blockchain import account, get_web3_provider, TRANSFER_WITH_AUTHORIZATION_ABI
from x402.chains import get_chain_id
from x402.types import (
    SettleResponse,
    VerifyResponse,
)
from app.schemas import VerifyRequest, SettleRequest

logger = logging.getLogger(__name__)


app = FastAPI(title="Facilitator")


@app.post("/verify")
async def verify(request: VerifyRequest):
    logger.info("Verifying payment")

    try:
        payment = request.payment_payload
        requirements = request.payment_requirements

        # Verify scheme matches
        if payment.scheme != requirements.scheme:
            return VerifyResponse(
                is_valid=False,
                invalid_reason=f"Payment scheme '{payment.scheme}' does not match required scheme '{requirements.scheme}'",
            )

        # Verify network matches
        if payment.network != requirements.network:
            return VerifyResponse(
                is_valid=False,
                invalid_reason=f"Payment network '{payment.network}' does not match required network '{requirements.network}'",
            )

        # Only support 'exact' scheme for now
        if payment.scheme != "exact":
            return VerifyResponse(
                is_valid=False, invalid_reason=f"Unsupported payment scheme: {payment.scheme}"
            )

        # Extract authorization and signature from payload
        payload = payment.payload
        signature = payload.signature
        auth = payload.authorization

        # Validate timestamp bounds
        current_time = int(time.time())
        valid_after = int(auth.valid_after)
        valid_before = int(auth.valid_before)

        if current_time < valid_after:
            return VerifyResponse(is_valid=False, invalid_reason="Payment not yet valid")

        if current_time > valid_before:
            return VerifyResponse(is_valid=False, invalid_reason="Payment has expired")

        # Validate amount
        if auth.value != requirements.max_amount_required:
            return VerifyResponse(
                is_valid=False,
                invalid_reason=f"Payment amount '{auth.value}' does not match required amount '{requirements.max_amount_required}'",
            )

        # Validate recipient
        if auth.to != requirements.pay_to:
            return VerifyResponse(
                is_valid=False,
                invalid_reason=f"Payment recipient '{auth.to}' does not match required recipient '{requirements.pay_to}'",
            )

        # Reconstruct EIP-712 typed data for signature verification
        nonce_hex = auth.nonce
        if nonce_hex.startswith("0x"):
            nonce_hex = nonce_hex[2:]
        nonce_bytes = bytes.fromhex(nonce_hex)

        typed_data = {
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"},
                ],
                "TransferWithAuthorization": [
                    {"name": "from", "type": "address"},
                    {"name": "to", "type": "address"},
                    {"name": "value", "type": "uint256"},
                    {"name": "validAfter", "type": "uint256"},
                    {"name": "validBefore", "type": "uint256"},
                    {"name": "nonce", "type": "bytes32"},
                ],
            },
            "primaryType": "TransferWithAuthorization",
            "domain": {
                "name": requirements.extra["name"],
                "version": requirements.extra["version"],
                "chainId": int(get_chain_id(requirements.network)),
                "verifyingContract": requirements.asset,
            },
            "message": {
                "from": auth.from_,
                "to": auth.to,
                "value": int(auth.value),
                "validAfter": valid_after,
                "validBefore": valid_before,
                "nonce": nonce_bytes,
            },
        }

        # Encode the typed data
        encoded_message = encode_typed_data(full_message=typed_data)

        # Recover the signer address from the signature
        recovered_address = Account.recover_message(encoded_message, signature=signature)

        # Verify the recovered address matches the 'from' address
        if recovered_address.lower() != auth.from_.lower():
            return VerifyResponse(
                is_valid=False,
                invalid_reason=f"Signature verification failed: recovered address {recovered_address} does not match sender {auth.from_}",
            )

        logger.info("Payment verified successfully")
        return VerifyResponse(is_valid=True, payer=recovered_address)

    except Exception as e:
        logger.error(f"Error verifying payment: {e}", exc_info=True)
        return VerifyResponse(is_valid=False, invalid_reason=f"Verification error: {e!s}")



@app.post("/settle")
async def settle(request: SettleRequest):
    logger.info("Settling payment")

    try:
        payment = request.payment_payload
        requirements = request.payment_requirements

        # Only support 'exact' scheme for now
        if payment.scheme != "exact":
            return SettleResponse(
                success=False, error_reason=f"Unsupported payment scheme: {payment.scheme}"
            )

        # Extract authorization and signature from payload
        payload = payment.payload
        signature = payload.signature
        auth = payload.authorization

        # Convert signature to bytes
        sig_bytes = bytes.fromhex(signature[2:] if signature.startswith("0x") else signature)
        if len(sig_bytes) != 65:
            return SettleResponse(
                success=False, error_reason=f"Invalid signature length: {len(sig_bytes)}"
            )

        # Get Web3 provider for the network
        try:
            w3 = get_web3_provider(payment.network)
        except ValueError as e:
            return SettleResponse(success=False, error_reason=str(e))

        # Check connection
        if not w3.is_connected():
            return SettleResponse(
                success=False, error_reason=f"Failed to connect to {payment.network} RPC"
            )

        # Create contract instance
        token_contract = w3.eth.contract(
            address=Web3.to_checksum_address(requirements.asset),
            abi=TRANSFER_WITH_AUTHORIZATION_ABI,
        )

        # Parse nonce
        nonce_hex = auth.nonce
        if nonce_hex.startswith("0x"):
            nonce_hex = nonce_hex[2:]
        nonce_bytes = bytes.fromhex(nonce_hex)

        # Build transaction
        tx = token_contract.functions.transferWithAuthorization(
            Web3.to_checksum_address(auth.from_),
            Web3.to_checksum_address(auth.to),
            int(auth.value),
            int(auth.valid_after),
            int(auth.valid_before),
            nonce_bytes,
            sig_bytes,
        ).build_transaction(
            {
                "from": account.address,
                "nonce": w3.eth.get_transaction_count(account.address),
                "gas": 200000,  # Estimate, can be adjusted
                "maxFeePerGas": w3.eth.gas_price * 2,
                "maxPriorityFeePerGas": w3.to_wei(1, "gwei"),
            }
        )

        # Sign and send transaction
        signed_tx = account.sign_transaction(tx)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        tx_hash_hex = tx_hash.hex()

        # Wait for transaction receipt (with timeout)
        try:
            receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
            if receipt.status == 1:
                logger.info(f"Settlement successful: {tx_hash_hex}")
                return SettleResponse(
                    success=True,
                    transaction=tx_hash_hex,
                    network=payment.network,
                    payer=auth.from_,
                )
            else:
                logger.error(f"Settlement transaction failed: {tx_hash_hex}")
                return SettleResponse(
                    success=False,
                    error_reason="Transaction reverted on chain",
                    transaction=tx_hash_hex,
                    network=payment.network,
                )
        except Exception as e:
            logger.warning(f"Transaction sent but receipt not confirmed: {e}")
            # Return success with transaction hash even if we can't wait for confirmation
            return SettleResponse(
                success=True,
                transaction=tx_hash_hex,
                network=payment.network,
                payer=auth.from_,
            )

    except Exception as e:
        logger.error(f"Error settling payment: {e}", exc_info=True)
        return SettleResponse(success=False, error_reason=f"Settlement error: {e!s}")
