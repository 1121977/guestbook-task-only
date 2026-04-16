package ru.scr.security.provider;

import org.springframework.core.io.Resource;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.InputStream;
import javax.xml.parsers.ParserConfigurationException;
import java.util.ArrayList;

public class XmlAuthenticationProvider implements AuthenticationProvider {

    final private Resource userDataResource;

    public XmlAuthenticationProvider(Resource userDataResource) {
        this.userDataResource = userDataResource;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        DocumentBuilderFactory builderFactory = DocumentBuilderFactory.newInstance();
        String userName = authentication.getName();
        String password = authentication.getCredentials().toString();
        try (InputStream inputStream = userDataResource.getInputStream()) {
            configureSecureXmlFactory(builderFactory);
            DocumentBuilder builder = builderFactory.newDocumentBuilder();
            Document xmlDocument = builder.parse(inputStream);
            if (!hasMatchingUser(xmlDocument, userName, password)) {
                throw new BadCredentialsException("Password is incorrect");
            }
        } catch (BadCredentialsException e) {
            throw e;
        } catch (Exception e) {
            throw new AuthenticationServiceException("Unable to authenticate user from XML", e);
        }

        Authentication resultAuthentication = new UsernamePasswordAuthenticationToken(authentication.getPrincipal(), authentication.getCredentials(), new ArrayList<>());
        return resultAuthentication;
    }

    private boolean hasMatchingUser(Document xmlDocument, String userName, String password) {
        NodeList users = xmlDocument.getElementsByTagName("User");
        for (int i = 0; i < users.getLength(); i++) {
            NodeList userFields = users.item(i).getChildNodes();
            String userNameValue = null;
            String passwordValue = null;
            for (int j = 0; j < userFields.getLength(); j++) {
                if ("UserName".equals(userFields.item(j).getNodeName())) {
                    userNameValue = userFields.item(j).getTextContent();
                }
                if ("Password".equals(userFields.item(j).getNodeName())) {
                    passwordValue = userFields.item(j).getTextContent();
                }
            }
            if (userName.equals(userNameValue) && password.equals(passwordValue)) {
                return true;
            }
        }
        return false;
    }

    private void configureSecureXmlFactory(DocumentBuilderFactory builderFactory) throws ParserConfigurationException {
        builderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        builderFactory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        builderFactory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        builderFactory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        builderFactory.setExpandEntityReferences(false);
        builderFactory.setXIncludeAware(false);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication == UsernamePasswordAuthenticationToken.class;
    }
}
