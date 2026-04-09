# Fixture: CWE-611 XML External Entity - Python
# VERDICT: TRUE_POSITIVE
# PATTERN: lxml_etree_parse_default
# SOURCE: function_parameter (file path)
# SINK: etree.parse
# TAINT_HOPS: 1
# NOTES: lxml default parser resolves external entities
from lxml import etree

def parse_xml(xml_file: str):
    # VULNERABLE: default lxml parser resolves external entities
    tree = etree.parse(xml_file)
    return tree.getroot()
