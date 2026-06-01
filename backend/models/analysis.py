from pydantic import BaseModel, ConfigDict


class PESection(BaseModel):
    model_config = ConfigDict(extra='ignore')

    name: str
    virtual_size: int
    raw_size: int
    entropy: float
    md5: str
    suspicious: bool


class ImportedFunction(BaseModel):
    model_config = ConfigDict(extra='ignore')

    dll: str
    function: str
    suspicious: bool


class YaraHit(BaseModel):
    model_config = ConfigDict(extra='ignore')

    rule_name: str
    description: str
    tags: list[str]
    matched_strings: list[str]


class StaticAnalysis(BaseModel):
    model_config = ConfigDict(extra='ignore')

    file_name: str
    file_size: int
    file_type: str
    md5: str
    sha1: str
    sha256: str
    pe_sections: list[PESection]
    imports: list[ImportedFunction]
    strings_extracted: list[str]
    yara_hits: list[YaraHit]
    is_packed: bool
    compile_timestamp: str | None
    entry_point: str


class MitreTechnique(BaseModel):
    model_config = ConfigDict(extra='ignore')

    technique_id: str
    technique_name: str
    tactic: str
    description: str
    confidence: int


class IoCs(BaseModel):
    model_config = ConfigDict(extra='ignore')

    ips: list[str]
    domains: list[str]
    urls: list[str]
    hashes: list[str]
    registry_keys: list[str]
    file_paths: list[str]
    mutexes: list[str]


class GroqAnalysis(BaseModel):
    model_config = ConfigDict(extra='ignore')

    malware_family: str
    confidence: int
    behavior_summary: str
    mitre_techniques: list[MitreTechnique]
    iocs: IoCs
    risk_level: str
    recommended_actions: list[str]
    analyst_notes: str
    raw_response: str = ""


class VirusTotalEngineHit(BaseModel):
    model_config = ConfigDict(extra='ignore')

    engine: str
    result: str


class VirusTotalResult(BaseModel):
    model_config = ConfigDict(extra='ignore')

    detection_ratio: str
    detections: int
    total_engines: int
    malicious: int
    suspicious: int
    undetected: int
    engine_hits: list[VirusTotalEngineHit]
    first_seen: str | None
    last_seen: str | None
    community_score: int
    vt_link: str
    family_names: list[str]


class AnalysisResult(BaseModel):
    model_config = ConfigDict(extra='ignore')

    analysis_id: str
    status: str
    created_at: str
    file_name: str
    static_analysis: StaticAnalysis | None
    groq_analysis: GroqAnalysis | None
    virustotal: VirusTotalResult | None
    error: str | None
