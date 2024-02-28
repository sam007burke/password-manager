import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOError;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.text.AttributedCharacterIterator.Attribute;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.crypto.dsig.TransformException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.*;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

/**
 * Manager
 */
public class Manager {

    private static final String algorithm = "AES";
    private String dbURL;
    private Document db;
    private String passwordHash;

    public static void main(String[] args) {
        

    }

    public void setDbURL(String dbURL) {

        this.dbURL = dbURL;
    }

    public void enterPassword(String password) throws NoSuchAlgorithmException {

        this.passwordHash = hashString(password);
    }

    public String getEncryptedContents() throws ParserConfigurationException, IOException, SAXException {

        Document doc = getFileDoc();
        doc.getDocumentElement().normalize();
        Node rootElement = doc.getDocumentElement();
        return rootElement.getLastChild().getTextContent();
    }

    private Document getFileDoc() throws ParserConfigurationException, IOException, SAXException {

        File f = new File(dbURL);
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document doc = db.parse(f);
        return doc;
    }

    private SecretKey getEncryptionKey() throws ParserConfigurationException, IOException, SAXException, NoSuchAlgorithmException, InvalidKeySpecException {

        Document doc = getFileDoc();
        doc.getDocumentElement().normalize();
        Node rootElement = doc.getDocumentElement();
        String salt = rootElement.getFirstChild().getAttributes().getNamedItem("salt").getTextContent();
        
        SecretKeyFactory scf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(passwordHash.toCharArray(), salt.getBytes(), 65536, 256);
        SecretKey secret = new SecretKeySpec(scf.generateSecret(spec).getEncoded(), algorithm);

        return secret;
    }

    public String hashString(String s) throws NoSuchAlgorithmException {

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(s.getBytes());
        return new String(digest.digest());
    }

    public void encryptDB() throws ParserConfigurationException, IOException, SAXException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, TransformerException, TransformerConfigurationException {

        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, getEncryptionKey());

        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer t = tf.newTransformer();
        DOMSource source = new DOMSource(this.db);
        StringWriter writer = new StringWriter();
        StreamResult result = new StreamResult(writer);
        t.transform(source, result);

        byte[] cipherText = cipher.doFinal(writer.toString().getBytes());
        String encrypted = Base64.getEncoder().encodeToString(cipherText);
        Document doc = getFileDoc();
        doc.getDocumentElement().getLastChild().setTextContent(encrypted);
        writeDocument(doc);
    }

    public void decryptDB() throws ParserConfigurationException, IOException, SAXException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException {

        String cipherText = getEncryptedContents();
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, getEncryptionKey());
        byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document decryptedDB = db.parse(new InputSource(new StringReader(new String(plainText))));
        this.db = decryptedDB;
    }

    public void addEntry(String ID, String username, String entryPassword) {

        Element entry = db.createElement("entry");
        Attr id = db.createAttribute("id");
        Attr u = db.createAttribute("username");
        Attr p = db.createAttribute("password");
        id.setTextContent(ID);
        u.setTextContent(username);
        p.setTextContent(entryPassword);
        entry.setAttributeNode(id);
        entry.setAttributeNode(u);
        entry.setAttributeNode(p);
        db.getDocumentElement().appendChild(entry);
    }

    public String retrieveUsername(String ID) {

        NodeList nodes = db.getDocumentElement().getChildNodes();
        int i = 0;
        Node currNode;
        while ((currNode = nodes.item(i++)) != null) {
            if (currNode.getAttributes().getNamedItem("id").getTextContent().equals(ID)) {
                return currNode.getAttributes().getNamedItem("username").getTextContent();
            }
        }
        return null;
    }

    public String retrievePassword(String ID) {

        NodeList nodes = db.getDocumentElement().getChildNodes();
        int i = 0;
        Node currNode;
        while ((currNode = nodes.item(i++)) != null) {
            if (currNode.getAttributes().getNamedItem("id").getTextContent().equals(ID)) {
                return currNode.getAttributes().getNamedItem("password").getTextContent();
            }
        }
        return null;
    }

    public void createDB() {

        try {

            DocumentBuilderFactory dbf = DocumentBuilderFactory.newDefaultInstance();
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.newDocument();
            Element rootElement = doc.createElement("passwords");
            doc.appendChild(rootElement);
            this.db = doc;
        } catch (Exception e) { System.out.println(e.getMessage());}
    }

    

    public void createFile() {

        try {

            // create a fresh dom object
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.newDocument();
            Element rootElement = doc.createElement("db");
            doc.appendChild(rootElement);

            Element header = doc.createElement("header");
            rootElement.appendChild(header);
            Element encrypted = doc.createElement("encrypted");
            rootElement.appendChild(encrypted);

            Attr salt = doc.createAttribute("salt");
            salt.setValue(generateSalt().toString());
            header.setAttributeNode(salt);

            Attr cipher = doc.createAttribute("cipher");
            cipher.setValue(algorithm);
            header.setAttributeNode(cipher);

            // here we would put encyrypted shit
            // encrypted.setTextContent("Hello, unencrypted world.");

            // write the new document as a file
            writeDocument(doc);
        }
        catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    private void writeDocument(Document doc) throws TransformerConfigurationException, TransformerException {

        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer t = tf.newTransformer();
        DOMSource source = new DOMSource(doc);
        StreamResult result = new StreamResult(new File(dbURL));
        t.transform(source, result);
    }

    private byte[] generateSalt() {

        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[16];
        random.nextBytes(bytes);
        return bytes;
    }
}