from eth_account.account import LocalAccount
from eth_account import Account
import os
from web3 import Web3
from x402.chains import get_chain_id
from dotenv import load_dotenv

load_dotenv()
facilitator_wallet = os.getenv("FACILITATOR_WALLET")
assert facilitator_wallet, "FACILITATOR_WALLET is not set"
account: LocalAccount = Account.from_key(facilitator_wallet)

# RPC endpoints for each network
RPC_URLS = {
    "84532": os.getenv("BASE_SEPOLIA_RPC", "https://sepolia.base.org"),
    "8453": os.getenv("BASE_RPC", "https://mainnet.base.org")
}

# EIP-3009 transferWithAuthorization ABI
TRANSFER_WITH_AUTHORIZATION_ABI = [
    {
        "inputs": [
            {"name": "from", "type": "address"},
            {"name": "to", "type": "address"},
            {"name": "value", "type": "uint256"},
            {"name": "validAfter", "type": "uint256"},
            {"name": "validBefore", "type": "uint256"},
            {"name": "nonce", "type": "bytes32"},
            {"name": "signature", "type": "bytes"},
        ],
        "name": "transferWithAuthorization",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    }
]


def get_web3_provider(network: str) -> Web3:
    """Get a Web3 provider for the given network."""
    chain_id = get_chain_id(network)
    rpc_url = RPC_URLS.get(chain_id)
    if not rpc_url:
        raise ValueError(f"No RPC URL configured for network {network} (chain_id: {chain_id})")
    return Web3(Web3.HTTPProvider(rpc_url))

