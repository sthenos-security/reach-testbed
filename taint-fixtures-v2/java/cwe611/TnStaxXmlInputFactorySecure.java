// Fixture: CWE-611 XML External Entity - Java
// VERDICT: TRUE_NEGATIVE
// PATTERN: stax_xmlinputfactory_xxe_disabled
// SOURCE: function_parameter (input stream)
// SINK: XMLInputFactory.createXMLStreamReader (hardened)
// TAINT_HOPS: 1
// NOTES: StAX API with DTD and external entities disabled - safe
// REAL_WORLD: elastic/elasticsearch XmlTextStructureFinderFactory.java
import javax.xml.stream.*;
import java.io.*;

public class TnStaxXmlInputFactorySecure {
    private static final XMLInputFactory XML_FACTORY;
    static {
        XML_FACTORY = XMLInputFactory.newInstance();
        XML_FACTORY.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XML_FACTORY.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
    }

    public void parseXml(InputStream input) throws Exception {
        // SAFE: DTD support and external entities disabled
        XMLStreamReader reader = XML_FACTORY.createXMLStreamReader(input);
        while (reader.hasNext()) { reader.next(); }
    }
}
