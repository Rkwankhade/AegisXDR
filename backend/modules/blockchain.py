"""
AegisXDR Blockchain-Based Audit Trail
Immutable ledger for Alerts, Incidents, Forensics, Evidence
"""
import hashlib
import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from core.config import settings


class BlockchainAuditTrail:
    """Simplified proof-of-work blockchain for audit immutability"""

    DIFFICULTY = 3  # Number of leading zeros required

    def __init__(self):
        self.chain: List[Dict] = []
        self.store_path = Path(settings.BLOCKCHAIN_STORE_PATH)
        self.store_path.mkdir(parents=True, exist_ok=True)
        self._load_chain()
        if not self.chain:
            self._create_genesis()

    def _create_genesis(self):
        genesis = self._create_block(
            previous_hash="0" * 64,
            data={"type": "genesis", "message": "AegisXDR Audit Chain Initialized"},
            data_type="genesis"
        )
        self.chain.append(genesis)
        self._persist_block(genesis)

    def _hash_block(self, block: Dict) -> str:
        block_copy = {k: v for k, v in block.items() if k != "hash"}
        block_str = json.dumps(block_copy, sort_keys=True, default=str)
        return hashlib.sha256(block_str.encode()).hexdigest()

    def _create_block(self, previous_hash: str, data: Dict,
                      data_type: str, tenant_id: str = "default",
                      nonce_start: int = 0) -> Dict:
        block = {
            "id": len(self.chain),
            "block_id": str(uuid.uuid4()),
            "previous_hash": previous_hash,
            "data": data,
            "data_type": data_type,
            "tenant_id": tenant_id,
            "timestamp": datetime.utcnow().isoformat(),
            "nonce": nonce_start,
            "hash": ""
        }
        # Proof of Work (lightweight for academic demo)
        while True:
            block["hash"] = self._hash_block(block)
            if block["hash"].startswith("0" * self.DIFFICULTY):
                break
            block["nonce"] += 1
        return block

    def add_entry(self, data: Dict, data_type: str,
                  tenant_id: str = "default") -> Dict:
        if not self.chain:
            self._create_genesis()
        previous_hash = self.chain[-1]["hash"]
        block = self._create_block(previous_hash, data, data_type, tenant_id)
        self.chain.append(block)
        self._persist_block(block)
        return {"block_id": block["block_id"], "hash": block["hash"],
                "block_number": block["id"], "timestamp": block["timestamp"]}

    def verify_chain(self) -> Dict:
        issues = []
        for i in range(1, len(self.chain)):
            curr = self.chain[i]
            prev = self.chain[i - 1]
            # Verify hash integrity
            expected = self._hash_block(curr)
            if curr["hash"] != expected:
                issues.append({"block": i, "issue": "Hash mismatch - possible tampering"})
            # Verify chain linkage
            if curr["previous_hash"] != prev["hash"]:
                issues.append({"block": i, "issue": "Previous hash mismatch - chain broken"})
            # Verify PoW
            if not curr["hash"].startswith("0" * self.DIFFICULTY):
                issues.append({"block": i, "issue": "Proof of work invalid"})

        return {
            "valid": len(issues) == 0,
            "chain_length": len(self.chain),
            "issues": issues,
            "verified_at": datetime.utcnow().isoformat()
        }

    def get_chain(self, tenant_id: str = None, data_type: str = None,
                  limit: int = 50) -> List[Dict]:
        chain = self.chain[:]
        if tenant_id:
            chain = [b for b in chain if b.get("tenant_id") == tenant_id]
        if data_type:
            chain = [b for b in chain if b.get("data_type") == data_type]
        # Return without sensitive internal details
        safe = []
        for b in chain[-limit:]:
            safe.append({
                "block_number": b["id"],
                "block_id": b["block_id"],
                "hash": b["hash"],
                "previous_hash": b["previous_hash"],
                "data_type": b["data_type"],
                "tenant_id": b["tenant_id"],
                "timestamp": b["timestamp"],
                "data": b["data"],
                "nonce": b["nonce"]
            })
        return safe

    def get_entry(self, block_id: str) -> Optional[Dict]:
        for block in self.chain:
            if block["block_id"] == block_id:
                return block
        return None

    def _persist_block(self, block: Dict):
        path = self.store_path / f"block_{block['id']:08d}.json"
        with open(path, "w") as f:
            json.dump(block, f, indent=2)

    def _load_chain(self):
        block_files = sorted(self.store_path.glob("block_*.json"))
        for bf in block_files:
            try:
                with open(bf) as f:
                    self.chain.append(json.load(f))
            except Exception:
                pass

    def get_stats(self) -> Dict:
        type_counts = {}
        for b in self.chain:
            t = b.get("data_type", "unknown")
            type_counts[t] = type_counts.get(t, 0) + 1
        return {
            "total_blocks": len(self.chain),
            "genesis_hash": self.chain[0]["hash"] if self.chain else None,
            "latest_hash": self.chain[-1]["hash"] if self.chain else None,
            "type_distribution": type_counts,
            "chain_valid": self.verify_chain()["valid"]
        }


# Singleton
blockchain = BlockchainAuditTrail()
