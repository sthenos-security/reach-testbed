// Fixture: CWE-611 XML External Entity - Java
// VERDICT: TRUE_NEGATIVE
// PATTERN: xml_parser_xxe_disabled
// SOURCE: http_request body
// SINK: DocumentBuilder.parse (hardened)
// TAINT_HOPS: 1
// NOTES: External entities explicitly disabled - safe against XXE
import javax.xml.parsers.*;
import java.io.*;

public class TnXmlParserSecure {
    public void parseXml(InputStream xmlInput) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        DocumentBuilder builder = factory.newDocumentBuilder();
        // SAFE: external entities disabled
        builder.parse(xmlInput);
    }
}
