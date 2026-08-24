from pydantic import BaseModel, IPvAnyAddress, Field
from typing import Optional, List, Dict, Any

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

class ZeekBaseConnection(BaseModel):
    timestamp: float = Field(alias="ts")
    uid: str
    source_ip: IPvAnyAddress = Field(alias="id.orig_h")
    source_port: int = Field(alias="id.orig_p")
    dest_ip: IPvAnyAddress = Field(alias="id.resp_h")
    dest_port: int = Field(alias="id.resp_p")

class ZeekDNS(ZeekBaseConnection):
    proto: Optional[str] = None
    query: Optional[str] = None
    qtype_name: Optional[str] = None
    rcode_name: Optional[str] = None
    answers: Optional[List[str]] = Field(default_factory=list)

class ZeekHTTP(ZeekBaseConnection):
    method: Optional[str] = None
    host: Optional[str] = None
    uri: Optional[str] = None
    user_agent: Optional[str] = None
    status_code: Optional[int] = None
    resp_fuids: Optional[List[str]] = Field(default_factory=list)

class ZeekSSL(ZeekBaseConnection):
    version: Optional[str] = None
    cipher: Optional[str] = None
    server_name: Optional[str] = None
    cert_chain_fuids: Optional[List[str]] = Field(default_factory=list)

class ZeekFiles(BaseModel):
    timestamp: float = Field(alias="ts")
    fuid: str
    conn_uids: Optional[List[str]] = Field(default_factory=list)
    filename: Optional[str] = None
    mime_type: Optional[str] = None
    md5: Optional[str] = None
    sha1: Optional[str] = None
    sha256: Optional[str] = None

class ZeekDHCP(BaseModel):
    timestamp: float = Field(alias="ts")
    uids: Optional[List[str]] = Field(default_factory=list)
    client_addr: Optional[IPvAnyAddress] = None
    mac: Optional[str] = None
    host_name: Optional[str] = None

class ZeekX509(BaseModel):
    timestamp: float = Field(alias="ts")
    id: str
    subject: Optional[str] = Field(alias="certificate.subject", default=None)
    issuer: Optional[str] = Field(alias="certificate.issuer", default=None)

class ZeekPE(BaseModel):
    timestamp: float = Field(alias="ts")
    id: str
    machine: Optional[str] = None
    os: Optional[str] = None
    is_exe: Optional[bool] = None

class ZeekOCSP(BaseModel):
    timestamp: float = Field(alias="ts")
    id: str
    certStatus: Optional[str] = None
    serialNumber: Optional[str] = None

class EcarEvent(BaseModel):
    timestamp_ms: int
    id: str
    hostname: str
    object: str
    action: str
    actorID: Optional[str] = None
    objectID: Optional[str] = None
    pid: Optional[int] = None
    ppid: Optional[int] = None
    tid: Optional[int] = None
    principal: Optional[str] = None
    properties: Dict[str, Any] = Field(default_factory=dict)

class WinEvent(BaseModel):
    timestamp: str 
    event_id: int
    hostname: str
    channel: str
    event_data: Dict[str, Any] = Field(default_factory=dict)

class SyslogEvent(BaseModel):
    timestamp: str
    hostname: str
    process: str
    message: str

class WebAccessEvent(BaseModel):
    source_ip: str
    timestamp: str
    method: str
    path: str
    status_code: int
    user_agent: str

class BashHistoryEvent(BaseModel):
    hostname: str
    username: str
    command: str

class AsaEvent(BaseModel):
    timestamp: str
    hostname: str
    message_id: str
    message: str

class IdsEvent(BaseModel):
    timestamp: str
    sig_id: str
    message: str
    classification: Optional[str] = None
    priority: Optional[int] = None
    protocol: str
    source_ip: str
    source_port: Optional[int] = None
    dest_ip: str
    dest_port: Optional[int] = None
