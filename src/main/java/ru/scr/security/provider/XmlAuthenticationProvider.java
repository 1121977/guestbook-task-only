package ru.scr.security.provider;

import org.springframework.core.io.Resource;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import javax.xml.XMLConstants;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;
import javax.xml.xpath.XPathVariableResolver;
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
            DocumentBuilderFactory builderFactory = DocumentBuilderFactory.newInstance();
            builderFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            builderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            builderFactory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            builderFactory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            builderFactory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            builderFactory.setXIncludeAware(false);
            builderFactory.setExpandEntityReferences(false);

            DocumentBuilder builder = builderFactory.newDocumentBuilder();
            Document xmlDocument = builder.parse(inputStream);

            XPath xPath = XPathFactory.newInstance().newXPath();
            xPath.setXPathVariableResolver(new XPathVariableResolver() {
                @Override
                public Object resolveVariable(QName variableName) {
                    if ("userName".equals(variableName.getLocalPart())) {
                        return userName;
                    } else if ("password".equals(variableName.getLocalPart())) {
                        return password;
                    }
                    return null;
                }
            });

            XPathExpression expression = xPath.compile(
                    "//User[UserName/text()=$userName and Password/text()=$password]");
            NodeList nodeList = (NodeList) expression.evaluate(xmlDocument, XPathConstants.NODESET);
            if (nodeList.getLength() == 0) {
                throw new BadCredentialsException("Password is incorrect");
            }
        } catch (BadCredentialsException e) {
            throw e;
        } catch (Exception e) {
            throw new AuthenticationServiceException("Authentication failed", e);
        }

        return new UsernamePasswordAuthenticationToken(
                authentication.getPrincipal(), authentication.getCredentials(), new ArrayList<>());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication == UsernamePasswordAuthenticationToken.class;
    }
}
