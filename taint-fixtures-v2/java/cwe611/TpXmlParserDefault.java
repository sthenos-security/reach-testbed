// Fixture: CWE-611 XML External Entity - Java
// VERDICT: TRUE_POSITIVE
// PATTERN: xml_parser_default_config
// SOURCE: http_request body
// SINK: DocumentBuilder.parse
// TAINT_HOPS: 1
// NOTES: Default XML parser allows external entities - XXE
// REAL_WORLD: elastic/elasticsearch, many Spring apps
import javax.xml.parsers.*;
import org.xml.sax.InputSource;
import java.io.*;

public class TpXmlParserDefault {
    public void parseXml(InputStream xmlInput) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        // VULNERABLE: default config allows external entities (XXE)
        builder.parse(xmlInput);
    }
}
