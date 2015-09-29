/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package ru.spb.iac.smev.mediation;

import com.firstlinesoftware.accessControlService.exceptions.CUDException;
import com.firstlinesoftware.accessControlService.utils.sign.XmlUtils;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.soap.*;
import javax.xml.transform.Source;
import javax.xml.transform.TransformerException;
import javax.xml.transform.stream.StreamSource;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.impl.OMNamespaceImpl;
import org.apache.axiom.om.impl.llom.OMAttributeImpl;
import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.commons.io.FileUtils;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.xml.security.transforms.TransformationException;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xpath.XPathAPI;
import org.springframework.ws.soap.axiom.support.AxiomUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;
import ru.CryptoPro.JCP.JCP;
import ru.CryptoPro.JCP.tools.Array;
import ru.CryptoPro.JCPxml.xmldsig.JCPXMLDSigInit;

import ru.spb.iac.smev.propertiesloader.GlobalProperties;

/**
 *
 * @author maleev
 */
public class Signer {

    private final PrivateKey privateKey;
    private final X509Certificate cert;
    private static final String WSSECURITY_SECEXT_URI = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
    private static final String WSSECURITY_UTILITY_URI = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
    private static final String SOAPENV_URI = "http://schemas.xmlsoap.org/soap/envelope/";
    private static final String XMLDSIG_URI = "http://www.w3.org/2000/09/xmldsig#";
    private static final String SMEV_URI = "http://smev.gosuslugi.ru/rev120315";
    Provider xmlDSigProvider = new ru.CryptoPro.JCPxml.dsig.internal.dom.XMLDSigRI();

    public Signer() throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, NoSuchProviderException {

        // Инициализация Transforms.
        com.sun.org.apache.xml.internal.security.Init.init();
        // Инициализация сервис-провайдера.
        if (!JCPXMLDSigInit.isInitialized()) {
            JCPXMLDSigInit.init();
        }
        // Инициализация ключевого контейнера и получение сертификата и закрытого ключа.
        KeyStore keyStore = KeyStore.getInstance(JCP.HD_STORE_NAME, "JCP");
        try {
            keyStore.load(null, null);
        } catch (IOException ex) {
            Logger.getLogger(Signer.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateException ex) {
            Logger.getLogger(Signer.class.getName()).log(Level.SEVERE, null, ex);
        }
        privateKey = (PrivateKey) keyStore.getKey(GlobalProperties.getInstance().getProperty("key.alias"), GlobalProperties.getInstance().getProperty("key.password").toCharArray());
        cert = (X509Certificate) keyStore.getCertificate(GlobalProperties.getInstance().getProperty("key.alias"));
    }

//    ***********************************************************************************
//      В кратце расскажу как работает xml подпись. Такую структуру мы должны получить:
//      <wsse:Security soapenv:actor="http://smev.gosuslugi.ru/actors/smev" soapenv:mustUnderstand="0" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
//         <wsse:BinarySecurityToken EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" wsu:Id="CertID-6ba60232-6130-1e51-37b7">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</wsse:BinarySecurityToken>
//         <ds:Signature Id="SigID-6ba604a8-6130-1e51-37b9" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
//            <ds:SignedInfo>
//               <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
//               <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411"/>
//               <ds:Reference URI="#SigID-6ba60462-6130-1e51-37b8">
//                  <ds:Transforms>
//                     <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
//                  </ds:Transforms>
//                  <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#gostr3411"/>
//                  <ds:DigestValue>8SRkFZilAagLE7r6I/eCaDKjkVroBG+DoOaVmFhK7Bw=</ds:DigestValue>
//               </ds:Reference>
//            </ds:SignedInfo>
//            <ds:SignatureValue>i3SJB0tnaUrj+9oi/zWq2gC60vQf+l3Iss/LiOcCZeW4sgSdGhlNV9Zo4bNZ3I+BPacy+5RRv2x/2oHhnY/X6A==</ds:SignatureValue>
//            <ds:KeyInfo>
//               <wsse:SecurityTokenReference>
//                  <wsse:Reference URI="#CertID-6ba60232-6130-1e51-37b7" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"/>
//               </wsse:SecurityTokenReference>
//            </ds:KeyInfo>
//         </ds:Signature>
//      </wsse:Security>
//      Зачем каждый тэг:
//      - тэг Security в основном только всё оборачивает и содержит аттрибут actor, который, грубо говоря, сообщает кому адресована данная подпись.
//      - BinnarySecurityToken содержит сертификат в base64
//      - Signature оборачивает всю информацию о подписи (как что подписывалось и соотвественно как проверить, ключи, значение подписи)
//      - SignedInfo - внутри информация о том, что подписывалось и как
//      - Reference - информация об одном элементе, который подписывается (таких тэгов может быть несколько). 
//        Аттрибут URI содержит ссылку на id эелемента, который подписывается. Reference внутри себя содержит:
//              - Tranforms - методы каноникализации подписываемого элемента (приведение xml к каноническому методу). Их можно задать несколько, они подряд будут применяться
//              - DigestMethod - указывается метод вычисления хэша элемента, который будет подписываться, после трансформации
//              - DigestValue - хэш элемента
//      - CanonicalizationMethod - метод каноникализации для элемента SignedInfo
//      - SignatureMethod - алгоритм подписи
//      - SignatureValue - значение подписи
//      - KeyInfo - информация о ключе
//      КАК работает:
//        Сначала формируется блок SignedInfo. Заполняются все методы, алгоритмы, значения хэшей (если мы "подписывем" несколько элементов). 
//        Но дело в том, что пока что мы ничего не подписываем. А на деле мы подписываем как раз блок SignedInfo. Т.е. после того как мы всё заполнили внутри него,
//        мы приводим его к каноническому виду по указанному методу в тэге CanonicalizationMethod, и подписываем сам блок. Значение подписи записываем в тэг SignatureValue.
//        Для проверки подписи нужно сделать наоборот - расшифровать подпись и посмотреть что у нас получился такой же блок SignedInfo если бы мы сделали это сами
//    
//      Почему метод подписи удаляет что то после подписывания:
//        тут дело в том, что информацию о ключе можно записать и в другом виде внутри KeyInfo, где кроме сертификата будет лежать отдельно ещё открытый ключ, информация
//        о том кто выпустил (в общем разложенный сертификат). Но нам нужен только сертификат. А вот стандартные средства как раз делают всё внутри KeyInfo. Поэтому мы оттуда
//        сертификат в base64 перекладываем в BinnarySecurityToken, а остальное удаляем
//    ******************************************************************************************    
    /**
     * На вход ожидаем SOAP Envelope (можно без soap:Header), который мы
     * переподпишем подписью СМЭВа. SOAPEnvelope сразу переводится в строку, так
     * что можно быстро поменять входные/выходные параметры.
     *
     * @param envelope org.apache.axiom.soap.SOAPEnvelope
     * @return переподписанный новый org.apache.axiom.soap.SOAPEnvelope
     */
    public SOAPEnvelope resignEnvelope(SOAPEnvelope envelope, boolean response, Integer cooperationType) throws SOAPException, XMLSignatureException, MarshalException, TransformerException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, TransformationException, WSSecurityException {
        /**
         * Сразу переводим envelope в SOAPMessage, чтобы было удобнее работать
         */
        MessageFactory mf = MessageFactory.newInstance();
        SOAPMessage message = mf.createMessage();
        SOAPPart soapPart = message.getSOAPPart();
        soapPart.setContent(new StreamSource(new java.io.StringReader(envelope.toString())));
        message.getSOAPPart().getEnvelope().addNamespaceDeclaration("ds", XMLDSIG_URI);


        Document doc = message.getSOAPPart().getEnvelope().getOwnerDocument();

        PreparedSignInfo preparedSignInfo = prepareHeader(message.getSOAPPart().getEnvelope(), cooperationType, response);



        /**
         * * Подпись данных **
         */
        WSSecHeader header = preparedSignInfo.getSecHeader();
        Element token = header.getSecurityHeader();
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM", xmlDSigProvider);
        // Указываем метод каноникализации для подписываемых элементов

        // Преобразования над подписываемым элементом (для блока Reference)
        List<Transform> transformList = new ArrayList<Transform>();
        Transform transformC14N =
                fac.newTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS, (XMLStructure) null);
        transformList.add(transformC14N);

        List<Reference> references = new LinkedList<Reference>();
        // Ссылка на подписываемые данные.
        Reference ref = fac.newReference("#" + preparedSignInfo.getBodyId(),
                fac.newDigestMethod("http://www.w3.org/2001/04/xmldsig-more#gostr3411", null),
                transformList, null, null);

        references.add(ref);

        //Если нужно подписать ещё и заголовок смэва, то указываем и его
        if (preparedSignInfo.getSmevHeaderId() != null) {
            Reference refSmevHeader = fac.newReference("#" + preparedSignInfo.getSmevHeaderId(),
                    fac.newDigestMethod("http://www.w3.org/2001/04/xmldsig-more#gostr3411", null),
                    transformList, null, null);

            references.add(refSmevHeader);
        }

        // Генерим Блок SignedInfo. Указываем метод каноникализации, алгоритм подписи и все ссылки на элементы
        SignedInfo si = fac.newSignedInfo(fac.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE,
                (C14NMethodParameterSpec) null),
                fac.newSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411", null),
                references);

        // Формируем Блок KeyInfo.
        KeyInfoFactory kif = fac.getKeyInfoFactory();
        X509Data x509d = kif.newX509Data(Collections.singletonList(cert));
        KeyInfo ki = kif.newKeyInfo(Collections.singletonList(x509d));

        // Подпись данных.
        javax.xml.crypto.dsig.XMLSignature sig = fac.newXMLSignature(si, ki);
        DOMSignContext signContext = new DOMSignContext(privateKey, token);
        sig.sign(signContext);

        // Блок подписи Signature.
        Element sigE = (Element) XPathAPI.selectSingleNode(signContext.getParent(), "//ds:Signature");
        // Блок данных KeyInfo.
        Node keyE = XPathAPI.selectSingleNode(sigE, "//ds:KeyInfo", sigE);

        // Ищем элемент BinarySecurityToken, который должен содержать сертификат. Кладем туда сертификат
        Element cerVal = (Element) XPathAPI.selectSingleNode(token, "//*[@wsu:Id='" + preparedSignInfo.getCertId() + "']");
        cerVal.setTextContent(XPathAPI.selectSingleNode(keyE, "//ds:X509Certificate", keyE).getFirstChild().getNodeValue());

        // Удаляем элементы KeyInfo, попавшие в тело документа. Поставим потом туда ссылку на сертификат
        keyE.removeChild(XPathAPI.selectSingleNode(keyE, "//ds:X509Data", keyE));

        NodeList chl = keyE.getChildNodes();

        for (int i = 0; i < chl.getLength(); i++) {
            keyE.removeChild(chl.item(i));
        }

        // Блок KeyInfo содержит указание на проверку подписи с помощью сертификата SenderCertificate.
        Node str = keyE.appendChild(doc.createElementNS("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
                "wsse:SecurityTokenReference"));
        Element strRef = (Element) str.appendChild(doc.createElementNS("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
                "wsse:Reference"));

        strRef.setAttribute("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3");
        strRef.setAttribute("URI", "#" + preparedSignInfo.getCertId());
        header.getSecurityHeader().appendChild(sigE);

        //Возвращает в виде org.apache.axiom.soap.SOAPEnvelope
        return AxiomUtils.toEnvelope(doc);
    }

    public PreparedSignInfo prepareHeader(javax.xml.soap.SOAPEnvelope envelope, Integer cooperationType, boolean response) throws SOAPException, WSSecurityException, TransformerException {

        PreparedSignInfo signInfo = new PreparedSignInfo();

        //Если взаимодействие Р-Ф и это запрос, то сразу сносим заголовок
        if (!response && cooperationType == CooperationTypes.REG_FED && envelope.getHeader() != null) {
            envelope.getHeader().detachNode();
        }

        //Проверяем есть ли вообще заголовок в Envelope
        if (envelope.getHeader() == null) {
            //создаем заголовок
            envelope.addHeader();
        }

        // Формируем заголовок.
        WSSecHeader header = new WSSecHeader();
        header.setActor(getActor(cooperationType, response));
        header.setMustUnderstand(false);

        signInfo.setSecHeader(header);
        // Привязываем заголовок к документу
        header.insertSecurityHeader(envelope.getOwnerDocument());

        // Подписываемый элемент.
        Element token = header.getSecurityHeader();
        Element binarySecurityToken = (Element) XPathAPI.selectSingleNode(token, "//wsse:BinarySecurityToken");
        if (binarySecurityToken == null) {
            //в нашем элементе Security нет такого тэга, создаем сами
            binarySecurityToken = (Element) token.appendChild(envelope.getOwnerDocument().createElementNS(WSSECURITY_SECEXT_URI, "wsse:BinarySecurityToken"));
            binarySecurityToken.setAttribute("EncodingType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary");
            binarySecurityToken.setAttribute("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3");
            token.appendChild(binarySecurityToken);
        }
        //Проставляем Id сертификата
        String certId = "CertId-" + UUID.randomUUID().toString();
        binarySecurityToken.setAttributeNS(WSSECURITY_UTILITY_URI, "wsu:Id", certId);
        signInfo.setCertId(certId);

        //Очищаем от остальных тэгов, которые могли остаться от прошлой подписи
        if (binarySecurityToken.getNextSibling() != null) {
            token.removeChild(binarySecurityToken.getNextSibling());
        }

        //Теперь надо узнать нужен ли нам вообще smev:Header и если да, то проставить его и узнать его Id
        signInfo.setSmevHeaderId(setSmevHeader(token, envelope, cooperationType, response));

        //смотрим есть ли wsu:Id у Body. Если нет - добавляем
        if (envelope.getBody().hasAttributeNS(WSSECURITY_UTILITY_URI, "Id")) {
            signInfo.setBodyId(envelope.getBody().getAttributeValue(new QName(WSSECURITY_UTILITY_URI, "Id")));
        } else {
            String bodyId = "BodyId-" + UUID.randomUUID().toString();
            envelope.getBody().setAttributeNS(WSSECURITY_UTILITY_URI, "wsu:Id", bodyId);
            signInfo.setBodyId(bodyId);
        }

        return signInfo;
    }

    /**
     * На основе типа взаимодействия определяет какой actor щас надо ставить
     *
     * @param cooperationType тип взаимодействия
     * @param isResponse сейчас ответ?
     * @return значение для аттрибута actor
     */
    private String getActor(Integer cooperationType, boolean isResponse) {
        switch (cooperationType.intValue()) {
            case CooperationTypes.REG_FED:
                return isResponse ? Actors.RECIPIENT : Actors.SMEV;
            case CooperationTypes.FED_REG:
                return isResponse ? Actors.SMEV : Actors.RECIPIENT;
            case CooperationTypes.REG_REG:
                return isResponse ? Actors.RECIPIENT : Actors.RECIPIENT;
            default:
                throw new CUDException("Неизвестный тип взаимодействия СМЭВ");

        }
    }
    private static SimpleDateFormat timeStampFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ");

    /**
     * Если нужно, то добавляется smev:Header в soap:Header и возвращается его
     * wsu:Id
     *
     * @param soapHeader
     * @param doc
     * @param cooperationType
     * @param isResponse
     * @return значение аттрибута wsu:Id
     * @throws TransformerException
     */
    private String setSmevHeader(Element securityHeader, javax.xml.soap.SOAPEnvelope envelope, Integer cooperationType, boolean isResponse) throws TransformerException, SOAPException {
        //Р - Ф запрос - ничего не делать
        //Р - Ф ответ - обновить smev:Header recipient
        //*******************************************
        //Ф - Р запрос - обновить smev:Header recipient
        //Ф - Р ответ - обновить smev:Header smev
        //*******************************************
        //Р - Р запрос - создать smev:Header recipient
        //Р - Р ответ - создать smev:Header recipient

        //Только в одном случае мы ничего не делаем
        if (cooperationType == CooperationTypes.REG_FED && !isResponse) {
            return null;
        }

        Document doc = envelope.getOwnerDocument();
        String CURRENT_SMEV_URI = SMEV_URI;
        //Попытаемся определить какой smev namespace используется в этом документе
        if (envelope.getBody().getFirstChild() != null) {

            Node messageNode = XPathAPI.selectSingleNode(envelope.getBody().getFirstChild(), "//*[local-name()='Message']");
            if (messageNode != null) {
                String probUri = messageNode.getNamespaceURI();
                if (probUri != null && probUri.length() > 0) {
                    CURRENT_SMEV_URI = probUri;
                }
            }
        }


        String actor = getActor(cooperationType, isResponse);
        //в остальных в общем нам не важно найти новый или создать (на всякий случай создаем)
        Element smevHeader = (Element) XPathAPI.selectSingleNode(securityHeader, "//smev:Header[@actor='" + actor + "']", doc.createElementNS(CURRENT_SMEV_URI, "smev:Header"));
        if (smevHeader == null) {
            smevHeader = doc.createElementNS(CURRENT_SMEV_URI, "smev:Header");
            smevHeader.setAttribute("actor", actor);
            smevHeader.setAttributeNS(WSSECURITY_UTILITY_URI, "wsu:Id", "smevHeaderId-" + UUID.randomUUID().toString());
            securityHeader.getParentNode().appendChild(smevHeader);

            Element nodeId = doc.createElementNS(CURRENT_SMEV_URI, "smev:NodeId");
            nodeId.setTextContent("78");
            smevHeader.appendChild(nodeId);

            Node requestId = XPathAPI.selectSingleNode(doc.getFirstChild(), "//*[local-name()='OriginRequestIdRef']");

            if (requestId != null) {
                Element messageId = doc.createElementNS(CURRENT_SMEV_URI, "smev:MessageId");
                messageId.setTextContent(requestId.getTextContent());
                smevHeader.appendChild(messageId);
            }

            Element timeStamp = doc.createElementNS(CURRENT_SMEV_URI, "smev:TimeStamp");
            timeStamp.setTextContent(timeStampFormat.format(new Date()));
            smevHeader.appendChild(timeStamp);

            Element messageClass = doc.createElementNS(CURRENT_SMEV_URI, "smev:MessageClass");
            messageClass.setTextContent(isResponse ? "RESPONSE" : "REQUEST");
            smevHeader.appendChild(messageClass);
        } else {
            Node timeStamp = smevHeader.getElementsByTagNameNS(CURRENT_SMEV_URI, "TimeStamp").item(0);
            timeStamp.setTextContent(timeStampFormat.format(new Date()));
        }

        return smevHeader.getAttributeNS(WSSECURITY_UTILITY_URI, "Id");
    }
}
