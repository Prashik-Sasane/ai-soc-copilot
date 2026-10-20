from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional


@dataclass
class ConnectorHealth:
    source_id: str
    connector_type: str
    vendor: Optional[str]
    status: str
    last_event_at: Optional[datetime]
    last_error: Optional[str]
    implemented: bool
    notes: str


class IngestConnector(ABC):
    """Vendor-agnostic connector contract. Implement pull() for SIEM/EDR pollers."""

    source_id: str
    display_name: str
    connector_type: str = "poller"
    vendor: Optional[str] = None

    @abstractmethod
    def health(self) -> ConnectorHealth:
        raise NotImplementedError

    def pull(self) -> list[dict[str, Any]]:
        raise NotImplementedError("This connector does not implement polling.")


class UnconfiguredVendorConnector(IngestConnector):
    """Placeholder so a Splunk/Elastic/Sentinel poller can be added without claiming it works."""

    def __init__(self, source_id: str, vendor: str):
        self.source_id = source_id
        self.display_name = f"{vendor} poller (not implemented)"
        self.connector_type = "vendor_poller"
        self.vendor = vendor

    def health(self) -> ConnectorHealth:
        return ConnectorHealth(
            source_id=self.source_id,
            connector_type=self.connector_type,
            vendor=self.vendor,
            status="disabled",
            last_event_at=None,
            last_error=None,
            implemented=False,
            notes=f"No {self.vendor} poller is implemented. Use the authenticated webhook/API connector.",
        )
