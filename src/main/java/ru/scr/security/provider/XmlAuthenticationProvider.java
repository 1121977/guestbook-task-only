package ru.scr.security.provider;

import org.springframework.core.io.Resource;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.InputStream;

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
            NodeList nodeList = xmlDocument.getElementsByTagName("User");
            if (!matchesUser(nodeList, userName, password)) {
                throw new BadCredentialsException("Password is incorrect");
            }
        } catch (BadCredentialsException e) {
            throw e;
        } catch (Exception e) {
            throw new AuthenticationServiceException("Failed to read authentication data", e);
        }

        Authentication resultAuthentication = new UsernamePasswordAuthenticationToken(
                authentication.getPrincipal(),
                authentication.getCredentials(),
                AuthorityUtils.NO_AUTHORITIES
        );
        return resultAuthentication;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication == UsernamePasswordAuthenticationToken.class;
    }

    private boolean matchesUser(NodeList users, String userName, String password) {
        for (int i = 0; i < users.getLength(); i++) {
            Element user = (Element) users.item(i);
            String storedUserName = getTagValue(user, "UserName");
            String storedPassword = getTagValue(user, "Password");
            if (userName.equals(storedUserName) && password.equals(storedPassword)) {
                return true;
            }
        }
        return false;
    }

    private String getTagValue(Element element, String tagName) {
        NodeList values = element.getElementsByTagName(tagName);
        if (values.getLength() == 0 || values.item(0).getTextContent() == null) {
            return "";
        }
        return values.item(0).getTextContent().trim();
    }
}
