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

    private String escapeXPathString(String value) {
      
        if (!value.contains("'")) {
            return "'" + value + "'";
        }
        StringBuilder sb = new StringBuilder("concat(");
        String[] parts = value.split("'", -1);
        for (int i = 0; i < parts.length; i++) {
            if (i > 0) sb.append(",\"'\",");
            sb.append("'").append(parts[i]).append("'");
        }
        sb.append(")");
        return sb.toString();
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        DocumentBuilderFactory builderFactory = DocumentBuilderFactory.newInstance();
        String userName = authentication.getName();
        String password = authentication.getCredentials().toString();
        try (InputStream inputStream = userDataResource.getInputStream()) {
            DocumentBuilder builder = builderFactory.newDocumentBuilder();
            Document xmlDocument = builder.parse(inputStream);
            XPath xPath = XPathFactory.newInstance().newXPath();
            String expression = "//User[UserName/text()=" + escapeXPathString(userName) + " and Password/text()=" + escapeXPathString(password) + "]";
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
