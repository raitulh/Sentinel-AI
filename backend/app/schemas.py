from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, HttpUrl, StringConstraints
from typing_extensions import Annotated

Name = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=180)]
Password = Annotated[str, StringConstraints(min_length=1, max_length=128)]


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    email: str
    full_name: str


class AuthOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserOut


class RegisterIn(BaseModel):
    email: str = Field(min_length=1, max_length=255)
    full_name: str = Field(default="Workspace User", min_length=1, max_length=180)
    password: str = Field(min_length=1, max_length=128)
    organization_name: str = Field(default="My Workspace", min_length=1, max_length=180)


class LoginIn(BaseModel):
    email: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=1, max_length=128)


class ProjectCreate(BaseModel):
    name: Name
    description: str = Field(default="", max_length=4000)


class ProjectOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    name: str
    description: str
    created_at: datetime
    updated_at: datetime


class TargetCreate(BaseModel):
    project_id: str
    name: Name
    url: str = Field(min_length=8, max_length=2048)
    authorization_acknowledged: bool
    authorization_note: str = Field(min_length=10, max_length=2000)


class TargetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    project_id: str
    name: str
    canonical_url: str
    scope_acknowledged: bool
    verification_method: str
    verified_at: datetime | None
    is_active: bool
    created_at: datetime


class ScanCreate(BaseModel):
    target_id: str
    scan_profile: Literal["safe_baseline"] = "safe_baseline"


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    project_id: str
    target_id: str
    status: str
    scan_profile: str
    progress: int
    current_stage: str
    error_summary: str | None
    scanner_versions: dict[str, Any]
    started_at: datetime | None
    finished_at: datetime | None
    created_at: datetime


class EvidenceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    evidence_type: str
    summary: str
    sanitized_data: dict[str, Any]
    content_hash: str
    created_at: datetime


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    project_id: str
    target_id: str
    scan_id: str
    rule_id: str
    title: str
    description: str
    severity: str
    confidence: str
    priority_score: int
    verification_status: str
    status: str
    location: str
    recommendation: str
    first_seen_at: datetime
    last_seen_at: datetime


class FindingDetail(FindingOut):
    evidence: list[EvidenceOut] = []
    remediation_template: dict[str, Any] = {}


class RemediationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    finding_id: str
    title: str
    rationale: str
    patch_diff: str
    test_plan: dict[str, Any]
    status: str
    reviewed_at: datetime | None
    created_at: datetime


class ReviewIn(BaseModel):
    decision: Literal["approved", "rejected"]
    comment: str = Field(default="", max_length=2000)
