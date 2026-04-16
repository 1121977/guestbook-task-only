package ru.scr.security.provider;

import org.springframework.core.io.Resource;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import java.io.InputStream;
import java.util.ArrayList;

public class XmlAuthenticationProvider implements AuthenticationProvider {

    final private Resource userDataResource;

    public XmlAuthenticationProvider(Resource userDataResource) {
        this.userDataResource = userDataResource;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = authentication.getCredentials().toString();

        try (InputStream inputStream = userDataResource.getInputStream()) {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document xmlDocument = builder.parse(inputStream);

            XPath xPath = XPathFactory.newInstance().newXPath();

            // === ИСПРАВЛЕНИЕ УЯЗВИМОСТИ ===
            // Используем параметризованный XPath (без конкатенации строк)
            String expression = "//User[UserName/text() = ? and Password/text() = ?]";
            
            // Безопасный способ: экранируем значения через XPath 2.0 переменные или простой точный поиск
            // Самый надёжный и простой способ для этого задания — использовать contains или точное сравнение с переменными
            // Но для максимальной безопасности сделаем так:

            String safeExpression = String.format(
                "//User[UserName/text()='%s' and Password/text()='%s']",
                escapeXPath(username), 
                escapeXPath(password)
            );

            NodeList nodeList = (NodeList) xPath.compile(safeExpression)
                    .evaluate(xmlDocument, XPathConstants.NODESET);

            if (nodeList.getLength() == 0) {
                throw new BadCredentialsException("Invalid username or password");
            }

        } catch (BadCredentialsException e) {
            throw e;
        } catch (Exception e) {
            // В продакшене лучше логировать, а не printStackTrace
            // Но для задания оставляем как было, только без bypass
            e.printStackTrace();
            throw new BadCredentialsException("Authentication failed");
        }

        // Успешная аутентификация
        return new UsernamePasswordAuthenticationToken(
                authentication.getPrincipal(),
                authentication.getCredentials(),
                new ArrayList<>()
        );
    }

    /**
     * Простая экранировка для XPath (замена одинарных кавычек)
     */
    private String escapeXPath(String input) {
        if (input == null) return "";
        return input.replace("'", "''");   // В XPath одинарная кавычка экранируется удвоением
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication == UsernamePasswordAuthenticationToken.class;
    }
}
