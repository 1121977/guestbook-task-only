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

            // === РРЎРџР РђР’Р›Р•РќРР• РЈРЇР—Р’РРњРћРЎРўР ===
            // РСЃРїРѕР»СЊР·СѓРµРј РїР°СЂР°РјРµС‚СЂРёР·РѕРІР°РЅРЅС‹Р№ XPath (Р±РµР· РєРѕРЅРєР°С‚РµРЅР°С†РёРё СЃС‚СЂРѕРє)
            String expression = "//User[UserName/text() = ? and Password/text() = ?]";
            
            // Р‘РµР·РѕРїР°СЃРЅС‹Р№ СЃРїРѕСЃРѕР±: СЌРєСЂР°РЅРёСЂСѓРµРј Р·РЅР°С‡РµРЅРёСЏ С‡РµСЂРµР· XPath 2.0 РїРµСЂРµРјРµРЅРЅС‹Рµ РёР»Рё РїСЂРѕСЃС‚РѕР№ С‚РѕС‡РЅС‹Р№ РїРѕРёСЃРє
            // РЎР°РјС‹Р№ РЅР°РґС‘Р¶РЅС‹Р№ Рё РїСЂРѕСЃС‚РѕР№ СЃРїРѕСЃРѕР± РґР»СЏ СЌС‚РѕРіРѕ Р·Р°РґР°РЅРёСЏ вЂ” РёСЃРїРѕР»СЊР·РѕРІР°С‚СЊ contains РёР»Рё С‚РѕС‡РЅРѕРµ СЃСЂР°РІРЅРµРЅРёРµ СЃ РїРµСЂРµРјРµРЅРЅС‹РјРё
            // РќРѕ РґР»СЏ РјР°РєСЃРёРјР°Р»СЊРЅРѕР№ Р±РµР·РѕРїР°СЃРЅРѕСЃС‚Рё СЃРґРµР»Р°РµРј С‚Р°Рє:

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
            // Р’ РїСЂРѕРґР°РєС€РµРЅРµ Р»СѓС‡С€Рµ Р»РѕРіРёСЂРѕРІР°С‚СЊ, Р° РЅРµ printStackTrace
            // РќРѕ РґР»СЏ Р·Р°РґР°РЅРёСЏ РѕСЃС‚Р°РІР»СЏРµРј РєР°Рє Р±С‹Р»Рѕ, С‚РѕР»СЊРєРѕ Р±РµР· bypass
            e.printStackTrace();
            throw new BadCredentialsException("Authentication failed");
        }

        // РЈСЃРїРµС€РЅР°СЏ Р°СѓС‚РµРЅС‚РёС„РёРєР°С†РёСЏ
        return new UsernamePasswordAuthenticationToken(
                authentication.getPrincipal(),
                authentication.getCredentials(),
                new ArrayList<>()
        );
    }

    /**
     * РџСЂРѕСЃС‚Р°СЏ СЌРєСЂР°РЅРёСЂРѕРІРєР° РґР»СЏ XPath (Р·Р°РјРµРЅР° РѕРґРёРЅР°СЂРЅС‹С… РєР°РІС‹С‡РµРє)
     */
    private String escapeXPath(String input) {
        if (input == null) return "";
        return input.replace("'", "''");   // Р’ XPath РѕРґРёРЅР°СЂРЅР°СЏ РєР°РІС‹С‡РєР° СЌРєСЂР°РЅРёСЂСѓРµС‚СЃСЏ СѓРґРІРѕРµРЅРёРµРј
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication == UsernamePasswordAuthenticationToken.class;
    }
}