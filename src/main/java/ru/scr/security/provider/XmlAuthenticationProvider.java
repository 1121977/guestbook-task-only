package ru.scr.security.provider;

import org.springframework.core.io.Resource;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.InputStream;
import java.util.ArrayList;

public class XmlAuthenticationProvider implements AuthenticationProvider {

    final private Resource userDataResource;

    public XmlAuthenticationProvider(Resource userDataResource) {
        this.userDataResource = userDataResource;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String userName = authentication.getName();
        String password = authentication.getCredentials().toString();
        try (InputStream inputStream = userDataResource.getInputStream()) {
            DocumentBuilder builder = createSecureDocumentBuilder();
            Document xmlDocument = builder.parse(inputStream);
            if (!isValidCredentials(xmlDocument, userName, password)) {
                throw new BadCredentialsException("Invalid username or password");
            }
        } catch (BadCredentialsException e) {
            throw e;
        } catch (Exception e) {
            throw new AuthenticationServiceException("Authentication backend failure", e);
        }

        Authentication resultAuthentication = new UsernamePasswordAuthenticationToken(authentication.getPrincipal(), authentication.getCredentials(), new ArrayList<>());
        return resultAuthentication;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication == UsernamePasswordAuthenticationToken.class;
    }

    private DocumentBuilder createSecureDocumentBuilder() throws ParserConfigurationException {
        DocumentBuilderFactory builderFactory = DocumentBuilderFactory.newInstance();
        builderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        builderFactory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        builderFactory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        builderFactory.setXIncludeAware(false);
        builderFactory.setExpandEntityReferences(false);
        return builderFactory.newDocumentBuilder();
    }

    private boolean isValidCredentials(Document xmlDocument, String userName, String password) {
        NodeList users = xmlDocument.getElementsByTagName("User");
        for (int i = 0; i < users.getLength(); i++) {
            Node user = users.item(i);
            if (!(user instanceof org.w3c.dom.Element userElement)) {
                continue;
            }

            String storedUserName = getTagValue(userElement, "UserName");
            String storedPassword = getTagValue(userElement, "Password");
            if (userName.equals(storedUserName) && password.equals(storedPassword)) {
                return true;
            }
        }
        return false;
    }

    private String getTagValue(org.w3c.dom.Element parent, String tagName) {
        NodeList nodes = parent.getElementsByTagName(tagName);
        if (nodes.getLength() == 0 || nodes.item(0) == null) {
            return "";
        }
        return nodes.item(0).getTextContent();
    }
}
