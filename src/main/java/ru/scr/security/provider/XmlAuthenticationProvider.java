package ru.scr.security.provider;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.URI;
import java.util.ArrayList;

public class XmlAuthenticationProvider implements AuthenticationProvider {

    final private Resource userDataResource;

    public XmlAuthenticationProvider(Resource userDataResource) {
        this.userDataResource = userDataResource;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        DocumentBuilderFactory builderFactory = DocumentBuilderFactory.newInstance();
        try {
            // Disable XXE
            builderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            builderFactory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            builderFactory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            builderFactory.setExpandEntityReferences(false);
        } catch (Exception e) {
            e.printStackTrace();
        }

        String userName = authentication.getName();
        String password = (authentication.getCredentials() != null) ? authentication.getCredentials().toString() : "";
        
        try (InputStream inputStream = userDataResource.getInputStream()) {
            DocumentBuilder builder = builderFactory.newDocumentBuilder();
            Document xmlDocument = builder.parse(inputStream);
            XPath xPath = XPathFactory.newInstance().newXPath();
            
            // To prevent XPath injection, we can fetch all users and check them in Java
            // or use a more complex XPath with variable resolvers. 
            // For a small file like users.xml, manual iteration is safe and efficient.
            NodeList nodeList = (NodeList) xPath.compile("//User").evaluate(xmlDocument, XPathConstants.NODESET);
            
            boolean authenticated = false;
            for (int i = 0; i < nodeList.getLength(); i++) {
                Node userNode = nodeList.item(i);
                String currentUserName = "";
                String currentPassword = "";
                
                NodeList children = userNode.getChildNodes();
                for (int j = 0; j < children.getLength(); j++) {
                    Node child = children.item(j);
                    if ("UserName".equals(child.getNodeName())) {
                        currentUserName = child.getTextContent();
                    } else if ("Password".equals(child.getNodeName())) {
                        currentPassword = child.getTextContent();
                    }
                }
                
                if (userName.equals(currentUserName) && password.equals(currentPassword)) {
                    authenticated = true;
                    break;
                }
            }

            if (!authenticated) {
                throw new BadCredentialsException("Invalid username or password");
            }
        } catch (BadCredentialsException e) {
            throw e;
        } catch (Exception e) {
            e.printStackTrace();
            throw new AuthenticationServiceException("Error during XML authentication", e);
        }

        return new UsernamePasswordAuthenticationToken(authentication.getPrincipal(), authentication.getCredentials(), new ArrayList<>());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication == UsernamePasswordAuthenticationToken.class;
    }
}
