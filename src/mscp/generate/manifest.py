# mscp/generate/scap.py

# Standard python modules
import argparse
import sys
import json
import datetime
from pathlib import Path


# Additional python modules

# Local python modules
from ..classes import Macsecurityrule
from ..classes import Baseline
from ..common_utils import (
    config,
    get_version_data,
    logger,
    mscp_data    
)
def generate_manifest(args: argparse.Namespace) -> None:    
    output_basename: str = args.baseline.name
    baseline_name: str = args.baseline.stem
    audit_name: str = str(baseline_name)
    build_path: Path = Path(config.get("output_dir", ""), baseline_name)
    custom: bool = not any(Path(config["custom"]["root_dir"]).iterdir())    
    baseline: Baseline = Baseline.from_yaml(args.baseline, "en", custom)    
    current_version_data: dict[str, Any] = get_version_data(
        baseline.platform["os"], baseline.platform["version"], mscp_data
    )
    manifest = {}    
    manifest["benchmark"] = audit_name
    manifest["parent_values"] = baseline.parent_values
    manifest["platform"] =  {
        "os": baseline.platform["os"],
        "version": baseline.platform["version"],
        "cpe": current_version_data["cpe"]
    }
    manifest["release_info"] = {
        "version" : current_version_data["revision"],
        "date": current_version_data["date"] 
    }        
    manifest["plist_location"] = "/Library/Preferences/org.{}.audit.plist".format(baseline_name)
    manifest["log_location"] = "/Library/Logs/{}_baseline.log".format(baseline_name)    
    manifest["creation_date"] = datetime.datetime.now().replace(microsecond=0).isoformat()
    manifest["rules"] = []
    for profile in baseline.profile:
        for rule in profile.rules:
            rule_manifest = {}
            rule_manifest["id"] = rule.rule_id
            rule_manifest["title"] = rule.title
            rule_manifest["discussion"] = rule.discussion                        
            ref_parts = []
            for org, refs in rule.references:
                if refs:                    
                    for item in refs:
                        try:                            
                            k, v = item
                            if v is not None:                                
                                vals = ','.join(str(i) for i in v)                                
                                if k == "benchmark":
                                    k = "cis_benchmark"
                                if k == "controls_v8":
                                    k = "cis_controls_v8"
                                ref_parts.append(f"{k}|{vals}")          
                        except ValueError as e:
                            continue
            rule_manifest["references"] = ";".join(str(x) for x in ref_parts)
            rule_manifest['tags'] = ",".join(str(x) for x in rule.tags)
            if rule.check:
                rule_manifest["check"] = rule.check
                rule_manifest["result"] = rule.result_value
            rule_manifest["fix"] = {}
            if rule.mobileconfig_info:                
                rule_manifest["fix"]["mobile_config_info"] = []
                for mcinfo in rule.mobileconfig_info:                    
                    profile = {}
                    for content in mcinfo.payload_content:
                        profile["domain"] = mcinfo.payload_type
                        for k,v in content.items():
                            profile["key"] = k
                            profile["value"] = v
                    rule_manifest["fix"]["mobile_config_info"].append(profile)
            if rule.ddm_info:                                                
                rule_manifest["fix"]["ddm_info"] = {}                          
                for ddminfo,value in rule.ddm_info.items():                    
                    rule_manifest["fix"]["ddm_info"].update({ddminfo:value})                    
            if rule.fix:
                rule_manifest["fix"]["script"] = rule.fix
            manifest['rules'].append(rule_manifest)    
    with open("{}_manifest.json".format(build_path), 'w', encoding='utf-8') as f:
        json.dump(manifest, f, ensure_ascii=False, indent=4)
            
    