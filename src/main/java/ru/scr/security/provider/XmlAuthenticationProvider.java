package ru.scr.security.provider;

import org.springframework.core.io.Resource;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import javax.xml.xpath.XPathVariableResolver;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

public class XmlAuthenticationProvider implements AuthenticationProvider {

    private final Resource userDataResource;

    public XmlAuthenticationProvider(Resource userDataResource) {
        this.userDataResource = userDataResource;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String userName = authentication.getName();
        String presentedPassword = authentication.getCredentials().toString();

        try (InputStream inputStream = userDataResource.getInputStream()) {
            // 1. Secure DocumentBuilder to prevent XXE (XML External Entity) attacks
            DocumentBuilderFactory builderFactory = DocumentBuilderFactory.newInstance();
            builderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            builderFactory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            builderFactory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            
            DocumentBuilder builder = builderFactory.newDocumentBuilder();
            Document xmlDocument = builder.parse(inputStream);

            // 2. Setup XPath with a Variable Resolver to prevent Injection
            XPath xPath = XPathFactory.newInstance().newXPath();
            MapVariableResolver resolver = new MapVariableResolver();
            resolver.addVariable("userName", userName);
            xPath.setXPathVariableResolver(resolver);

            // Parameterized query: prevents an attacker from escaping the string context
            String expression = "//User[UserName/text()=$userName]";
            Node userNode = (Node) xPath.compile(expression).evaluate(xmlDocument, XPathConstants.NODE);

            // 3. Validation Logic
            if (userNode == null) {
                throw new BadCredentialsException("User not found");
            }

            // Extract the password stored in the XML
            String storedPassword = xPath.evaluate("Password/text()", userNode);

            // 4. Plaintext Comparison (As requested)
            if (storedPassword == null || !storedPassword.equals(presentedPassword)) {
                throw new BadCredentialsException("Invalid password");
            }

            // Return successful authentication token
            return new UsernamePasswordAuthenticationToken(
                    userName, 
                    null, // Credentials cleared for safety
                    new ArrayList<>()
            );

        } catch (AuthenticationException e) {
            throw e;
        } catch (Exception e) {
            // General catch to prevent leaking system details, but logging the error is advised
            throw new BadCredentialsException("Authentication error occurred");
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }

    /**
     * Helper class to map XPath variables to Java strings safely.
     * This ensures inputs are treated as data, not as executable code.
     */
    private static class MapVariableResolver implements XPathVariableResolver {
        private final Map<QName, Object> variables = new HashMap<>();

        public void addVariable(String name, Object value) {
            variables.put(new QName(name), value);
        }

        @Override
        public Object resolveVariable(QName variableName) {
            return variables.get(variableName);
        }
    }
}