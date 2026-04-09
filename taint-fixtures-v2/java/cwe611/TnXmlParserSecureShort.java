// Fixture: CWE-611 XML External Entity - Java
// VERDICT: TRUE_NEGATIVE
// PATTERN: xml_parser_disallow_doctype
// SOURCE: http_request body
// SINK: DocumentBuilder.parse (hardened)
// TAINT_HOPS: 1
// NOTES: Disallow DOCTYPE declaration - simplest XXE fix
import javax.xml.parsers.*;
import javax.xml.XMLConstants;
import java.io.*;

public class TnXmlParserSecureShort {
    public void parseXml(InputStream xmlInput) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        DocumentBuilder builder = factory.newDocumentBuilder();
        // SAFE: external DTD and schema access blocked
        builder.parse(xmlInput);
    }
}
