"""
Rule Generator
Generates IDS rules based on ML decisions
"""

def generate_snort_rule(attack_type, confidence):
    if attack_type == "ssh_bruteforce":
        return f"""
alert tcp any any -> any 22 (
  msg:"Potential SSH brute force (ML confidence={confidence:.2f})";
  flow:to_server,established;
  detection_filter:track by_src, count 5, seconds 60;
  classtype:attempted-admin;
  sid:1000003;
  rev:1;
)
"""
    return None
