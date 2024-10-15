# macsecurityrule.py
import logging

from dataclasses import dataclass
from typing import List

logger = logging.getLogger(__name__)

class MacSecurityRule:
    def __init__(
        self,
        title,
        rule_id,
        severity,
        discussion,
        check,
        fix,
        cci,
        cce,
        nist_controls,
        nist_171,
        disa_stig,
        srg,
        sfr,
        cis,
        cmmc,
        indigo,
        custom_refs,
        odv,
        tags,
        result_value,
        mobileconfig,
        mobileconfig_info,
        customized,
    ):
        self.rule_title = title
        self.rule_id = rule_id
        self.rule_severity = severity
        self.rule_discussion = discussion
        self.rule_check = check
        self.rule_fix = fix
        self.rule_cci = cci
        self.rule_cce = cce
        self.rule_80053r5 = nist_controls
        self.rule_800171 = nist_171
        self.rule_disa_stig = disa_stig
        self.rule_srg = srg
        self.rule_sfr = sfr
        self.rule_cis = cis
        self.rule_cmmc = cmmc
        self.rule_indigo = indigo
        self.rule_custom_refs = custom_refs
        self.rule_odv = odv
        self.rule_result_value = result_value
        self.rule_tags = tags
        self.rule_mobileconfig = mobileconfig
        self.rule_mobileconfig_info = mobileconfig_info
        self.rule_customized = customized


@dataclass
class Cis():
    benchmark: List[str]
    controls_v8: List[float]


@dataclass
class MacSecurityRule_new():
    title: str
    rule_id: str
    severity: str
    discussion: str
    check: str
    fix: str
    cci: List[str]
    cce: List[str]
    nist_controls: List[str]
    nist_171: List[str]
    disa_stig: List[str]
    srg: List[str]
    sfr: List[str]
    cis: Cis
    cmmc: List[str]
    indigo: List[str]
    custom_refs: List[str]
    odv: List[str]
    tags: List[str]
    result_value: str
    mobileconfig: str
    mobileconfig_info: str
    customized: bool


