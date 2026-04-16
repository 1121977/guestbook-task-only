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
        String userName = authentication.getName();
        String password = authentication.getCredentials().toString();
        try (InputStream inputStream = userDataResource.getInputStream()) {
            DocumentBuilder builder = builderFactory.newDocumentBuilder();
            Document xmlDocument = builder.parse(inputStream);
            
            XPath xPath = XPathFactory.newInstance().newXPath();

            xPath.setXPathVariableResolver(variableName -> {
                String name = variableName.getLocalPart();
                if ("user".equals(name)) return userName;
                if ("pass".equals(name)) return password;
                return null;
            });

            String expression = "//User[UserName/text()=$user and Password/text()=$pass]";
            
            NodeList nodeList = (NodeList) xPath.evaluate(expression, xmlDocument, XPathConstants.NODESET);
            
            if (nodeList == null || nodeList.getLength() == 0) {
                throw new BadCredentialsException("Password is incorrect");
            }
        } catch (BadCredentialsException e) {
            throw e;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return new UsernamePasswordAuthenticationToken(authentication.getPrincipal(), authentication.getCredentials(), new ArrayList<>());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication == UsernamePasswordAuthenticationToken.class;
    }
}
