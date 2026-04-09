# Fixture: CWE-611 XML External Entity - Python
# VERDICT: TRUE_NEGATIVE
# PATTERN: defusedxml_safe_parser
# SOURCE: function_parameter
# SINK: defusedxml.parse
# TAINT_HOPS: 1
# NOTES: defusedxml library blocks XXE by default
import defusedxml.ElementTree as ET

def parse_xml_safe(xml_file: str):
    # SAFE: defusedxml blocks external entities, DTDs, etc.
    tree = ET.parse(xml_file)
    return tree.getroot()
