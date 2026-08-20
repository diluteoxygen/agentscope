"""
Data models and canonical schemas for AgentScope capability fingerprints.
"""

from __future__ import annotations
import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class FilesystemCapabilities:
    read: List[str] = field(default_factory=list)
    write: List[str] = field(default_factory=list)

    def canonicalize(self) -> None:
        self.read = sorted(list(set(self.read)))
        self.write = sorted(list(set(self.write)))


@dataclass
class RunMetadata:
    agent: str
    command: List[str]
    timestamp: str
    duration_ms: int
    exit_code: int
    cwd: str
    hostname: Optional[str] = None


@dataclass
class Capabilities:
    filesystem: FilesystemCapabilities = field(default_factory=FilesystemCapabilities)
    commands: List[str] = field(default_factory=list)
    network: List[str] = field(default_factory=list)
    secrets: List[str] = field(default_factory=list)

    def canonicalize(self) -> None:
        self.filesystem.canonicalize()
        self.commands = sorted(list(set(self.commands)))
        self.network = sorted(list(set(self.network)))
        self.secrets = sorted(list(set(self.secrets)))


@dataclass
class CapabilityFingerprint:
    schema_version: str = "1.0"
    metadata: Optional[RunMetadata] = None
    capabilities: Capabilities = field(default_factory=Capabilities)

    def canonicalize(self) -> CapabilityFingerprint:
        self.capabilities.canonicalize()
        return self

    def to_dict(self) -> Dict[str, Any]:
        self.canonicalize()
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> CapabilityFingerprint:
        meta_dict = data.get("metadata")
        meta = RunMetadata(**meta_dict) if meta_dict else None
        
        cap_dict = data.get("capabilities", {})
        fs_dict = cap_dict.get("filesystem", {})
        fs = FilesystemCapabilities(
            read=fs_dict.get("read", []),
            write=fs_dict.get("write", [])
        )
        
        caps = Capabilities(
            filesystem=fs,
            commands=cap_dict.get("commands", []),
            network=cap_dict.get("network", []),
            secrets=cap_dict.get("secrets", [])
        )
        
        fp = cls(
            schema_version=data.get("schema_version", "1.0"),
            metadata=meta,
            capabilities=caps
        )
        fp.canonicalize()
        return fp

    @classmethod
    def from_json(cls, json_str: str) -> CapabilityFingerprint:
        data = json.loads(json_str)
        return cls.from_dict(data)


@dataclass
class CapabilityDelta:
    added_files_read: List[str] = field(default_factory=list)
    removed_files_read: List[str] = field(default_factory=list)
    added_files_written: List[str] = field(default_factory=list)
    removed_files_written: List[str] = field(default_factory=list)
    added_commands: List[str] = field(default_factory=list)
    removed_commands: List[str] = field(default_factory=list)
    added_network: List[str] = field(default_factory=list)
    removed_network: List[str] = field(default_factory=list)
    added_secrets: List[str] = field(default_factory=list)
    removed_secrets: List[str] = field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.LOW
    risk_reasons: List[str] = field(default_factory=list)

    @property
    def has_escalations(self) -> bool:
        return bool(
            self.added_files_read
            or self.added_files_written
            or self.added_commands
            or self.added_network
            or self.added_secrets
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "has_escalations": self.has_escalations,
            "risk_level": self.risk_level.value,
            "risk_reasons": self.risk_reasons,
            "added": {
                "files_read": sorted(self.added_files_read),
                "files_written": sorted(self.added_files_written),
                "commands": sorted(self.added_commands),
                "network": sorted(self.added_network),
                "secrets": sorted(self.added_secrets),
            },
            "removed": {
                "files_read": sorted(self.removed_files_read),
                "files_written": sorted(self.removed_files_written),
                "commands": sorted(self.removed_commands),
                "network": sorted(self.removed_network),
                "secrets": sorted(self.removed_secrets),
            }
        }
