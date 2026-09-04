# Real Device Dataset

Status: 10 verified real production device configurations discovered (Internet2 backbone).
Provenance: VERIFIED_REAL_PRODUCTION_DEVICE
Total Count: 0 (baseline public snippets)
Real Device Flag: false (in standard snippet dataset)
Vendor: Juniper Networks (JunOS 12.3R6.6, MX series)
Source: nsg-ethz/config2spec (USENIX NSDI '20), Internet2 backbone routers

## Discovered Configurations

The Config2Spec repository (ETH Zurich NSG group) contains 10 real Internet2
backbone router configurations. The repository README explicitly distinguishes
these from the synthesized configs: "With the exception of Internet2, the configs
have been synthesized using NetComplete."

These configs require sanitization before inclusion (they contain real Internet2
IP addresses and RADIUS server addresses).

## Additional Dataset Available by Request

The Purdue University ISL hosts ~1,600 anonymized Cisco router/switch configs
from a real production campus network. Access requires academic request at:
https://engineering.purdue.edu/~isl/network-config/data.html

## Research Gaps

Missing real-device configurations for: Stormshield, Sophos, WatchGuard, Barracuda,
A10, Forcepoint, SonicWall, Check Point, Fortinet, Palo Alto, Arista, Extreme,
Nokia, Allied Telesis, Huawei, Ubiquiti, HPE Aruba, D-Link, Ruijie, Cisco (Meraki,
Firepower), and all other vendors.

An exhaustive search of 47+ public sources (GitHub, GitLab, Kaggle, Zenodo, Figshare,
HuggingFace, Internet Archive, IEEE DataPort, vendor organizations, academic
repositories) found no publicly accessible real production configs for these vendors.
