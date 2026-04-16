package ru.scr.security.provider;

import org.springframework.core.io.Resource;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.*;
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
        String password = authentication.getCredentials().toString();
        
        // Проверка на пустые учетные данные
        if (userName == null || userName.trim().isEmpty()) {
            throw new BadCredentialsException("Username cannot be empty");
        }
        if (password == null || password.isEmpty()) {
            throw new BadCredentialsException("Password cannot be empty");
        }
        
        try (InputStream inputStream = userDataResource.getInputStream()) {
            // Настройка безопасного DocumentBuilderFactory
            DocumentBuilderFactory builderFactory = DocumentBuilderFactory.newInstance();
            builderFactory.setNamespaceAware(false);
            builderFactory.setValidating(false);
            
            // Защита от XXE (XML External Entity) атак
            builderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            builderFactory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            builderFactory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            builderFactory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            builderFactory.setXIncludeAware(false);
            builderFactory.setExpandEntityReferences(false);
            
            DocumentBuilder builder = builderFactory.newDocumentBuilder();
            Document xmlDocument = builder.parse(inputStream);
            
            XPath xPath = XPathFactory.newInstance().newXPath();
            
            // Использование параметризованного запроса для защиты от XPath Injection
            String expression = "//User[UserName/text()=$userName and Password/text()=$password]";
            
            // Создаем карту переменных
            Map<String, String> variables = new HashMap<>();
            variables.put("userName", userName);
            variables.put("password", password);
            
            // Устанавливаем resolver для переменных
            xPath.setXPathVariableResolver(new XPathVariableResolver() {
                @Override
                public Object resolveVariable(QName variableName) {
                    String name = variableName.getLocalPart();
                    return variables.get(name);
                }
            });
            
            // Выполняем XPath запрос
            NodeList nodeList = (NodeList) xPath.compile(expression).evaluate(xmlDocument, XPathConstants.NODESET);
            
            // Проверяем результат
            if (nodeList == null || nodeList.getLength() == 0) {
                throw new BadCredentialsException("Invalid username or password");
            }
            
            // Дополнительная проверка - должен быть найден ровно один пользователь
            if (nodeList.getLength() > 1) {
                throw new AuthenticationServiceException("Multiple users found with same credentials");
            }
            
        } catch (BadCredentialsException e) {
            throw e;
        } catch (AuthenticationServiceException e) {
            throw e;
        } catch (Exception e) {
            // Не раскрываем детали системных ошибок пользователю
            throw new AuthenticationServiceException("Authentication failed due to system error", e);
        }
        
        // Создаем аутентифицированный токен
        return new UsernamePasswordAuthenticationToken(userName, null, new ArrayList<>());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication == UsernamePasswordAuthenticationToken.class;
    }
}