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
            builderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            builderFactory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            builderFactory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            builderFactory.setXIncludeAware(false);
            builderFactory.setExpandEntityReferences(false);
        } catch (Exception e) {
            e.printStackTrace();
        }

        String userName = authentication.getName();
        String password = authentication.getCredentials().toString();

        if (userName.contains("'") || userName.contains("\"") || password.contains("'") || password.contains("\"")) {
            throw new BadCredentialsException("Invalid characters in credentials");
        }

        try (InputStream inputStream = userDataResource.getInputStream()) {
            DocumentBuilder builder = builderFactory.newDocumentBuilder();
            Document xmlDocument = builder.parse(inputStream);
            XPath xPath = XPathFactory.newInstance().newXPath();
            String expression = "//User[UserName/text()='" + userName + "' and" + " Password/text()='" + password + "']";
            NodeList nodeList = (NodeList) xPath.compile(expression).evaluate(xmlDocument, XPathConstants.NODESET);
            if (nodeList.getLength() == 0) {
                throw new BadCredentialsException("Password is incorrect");
            }
        } catch (BadCredentialsException e) {
            throw e;
        } catch (Exception e) {
            e.printStackTrace();
        }

        Authentication resultAuthentication = new UsernamePasswordAuthenticationToken(authentication.getPrincipal(), authentication.getCredentials(), new ArrayList<>());
        return resultAuthentication;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication == UsernamePasswordAuthenticationToken.class;
    }
}