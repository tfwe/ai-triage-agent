from pydantic import BaseModel, IPvAnyAddress, Field
from typing import Optional

class ZeekConnection(BaseModel):
    timestamp: float = Field(alias="ts")
    uid: str
    source_ip: IPvAnyAddress = Field(alias="id.orig_h")
    source_port: int = Field(alias="id.orig_p")
    dest_ip: IPvAnyAddress = Field(alias="id.resp_h")
    dest_port: int = Field(alias="id.resp_p")
    protocol: str = Field(alias="proto")
    bytes_sent: Optional[int] = Field(alias="orig_bytes", default=0)
    bytes_received: Optional[int] = Field(alias="resp_bytes", default=0)
    state: Optional[str] = Field(alias="conn_state", default=None)
