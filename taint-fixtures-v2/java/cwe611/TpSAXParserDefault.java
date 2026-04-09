// Fixture: CWE-611 XML External Entity - Java
// VERDICT: TRUE_POSITIVE
// PATTERN: sax_parser_default_config
// SOURCE: http_request body
// SINK: SAXParser.parse
// TAINT_HOPS: 1
// NOTES: Default SAXParser allows external entities
import javax.xml.parsers.*;
import org.xml.sax.helpers.DefaultHandler;
import java.io.*;

public class TpSAXParserDefault {
    public void parseXml(InputStream xmlInput) throws Exception {
        SAXParserFactory factory = SAXParserFactory.newInstance();
        SAXParser parser = factory.newSAXParser();
        // VULNERABLE: default SAXParser allows XXE
        parser.parse(xmlInput, new DefaultHandler());
    }
}
