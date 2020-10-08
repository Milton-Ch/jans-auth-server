package org.gluu.oxauth.model.uma;

import org.apache.commons.io.IOUtils;
import io.jans.as.model.uma.JsonLogicNode;
import io.jans.as.model.uma.JsonLogicNodeParser;
import org.testng.annotations.Test;

import java.io.IOException;

import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

/**
 * @author yuriyz
 */
public class JsonLogicNodeParserTest {

    @Test
    public void parse() throws IOException {
        String json = IOUtils.toString(JsonLogicNodeParserTest.class.getClassLoader().getResourceAsStream("json-logic-node.json"));
        JsonLogicNode node = JsonLogicNodeParser.parseNode(json);

        assertNotNull(node);
        assertTrue(node.isValid());
    }
}
