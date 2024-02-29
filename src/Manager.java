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
import java.util.Collections;
import java.util.HashSet;

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
    private HashSet<String> allowedAttributes = new HashSet<>();

    public static void main(String[] args) {
        

    }

    public Manager() {
        
        Collections.addAll(allowedAttributes, "title", "url", "username", "password");
    }

    public void setDbURL(String dbURL) {

        this.dbURL = dbURL;
    }

    public void enterPassword(String password) throws EncryptionException {

        this.passwordHash = hashString(password);
    }

    // public void openDB(String dbURL, String password)

    public String getEncryptedContents() throws FileAccessException {

        Document doc = getFileDoc();
        doc.getDocumentElement().normalize();
        Node rootElement = doc.getDocumentElement();
        return rootElement.getLastChild().getTextContent();
    }

    private Document getFileDoc() throws FileAccessException {

        try {

            File f = new File(dbURL);
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(f);
            return doc;
        }
        catch (ParserConfigurationException | IOException | SAXException e) {

            throw new FileAccessException(e.getMessage());
        }
    }

    private SecretKey getEncryptionKey() throws FileAccessException, EncryptionException {

        Document doc = getFileDoc();
        doc.getDocumentElement().normalize();
        Node rootElement = doc.getDocumentElement();
        String salt = rootElement.getFirstChild().getAttributes().getNamedItem("salt").getTextContent();
        
        try {
        
            SecretKeyFactory scf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(passwordHash.toCharArray(), salt.getBytes(), 65536, 256);
            SecretKey secret = new SecretKeySpec(scf.generateSecret(spec).getEncoded(), algorithm);
            return secret;
        }
        catch (InvalidKeySpecException | NoSuchAlgorithmException e) {

            throw new EncryptionException("Could not generate encryption key: " + e.getMessage());
        }
    }

    public String hashString(String s) throws EncryptionException {

        try {
        
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(s.getBytes());
            return new String(digest.digest());
        }
        catch (NoSuchAlgorithmException e) {

            throw new EncryptionException("Cannot hash given string. (invalid hash algorithm).");
        }
    }

    public void encryptDB() throws EncryptionException, FileAccessException, DBFormatException {

        try{

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
        catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {

            throw new EncryptionException("Cannot encrypt database: " + e.getMessage());
        }
        catch (TransformerException e) {

            throw new DBFormatException("Cannot prepare database for encryption: " + e.getMessage());
        }
    }

    public void decryptDB() throws FileAccessException, EncryptionException, DBFormatException {

        try {

            String cipherText = getEncryptedContents();
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.DECRYPT_MODE, getEncryptionKey());
            byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document decryptedDB = db.parse(new InputSource(new StringReader(new String(plainText))));
            this.db = decryptedDB;
        }
        catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | InvalidKeyException | BadPaddingException e) {

            throw new EncryptionException("Cannot decrypt database: " + e.getMessage());
        }
        catch (ParserConfigurationException | IOException | SAXException e) {

            throw new DBFormatException("Cannot parse database decrypt: " + e.getMessage());
        }
    }

    public void addEntry(String title, String URL, String username, String entryPassword) throws DBFormatException {

        if (db == null) {
            throw new DBFormatException("Database not yet loaded.");
        }

        int entryID = Integer.parseInt(db.getDocumentElement().getAttribute("nextID"));
        db.getDocumentElement().setAttribute("nextID", String.valueOf(entryID + 1));

        Element entry = db.createElement("entry");
        entry.setAttribute("id", String.valueOf(entryID));
        entry.setAttribute("title", title);
        entry.setAttribute("url", URL);
        entry.setAttribute("username", username);
        entry.setAttribute("password", entryPassword);
        db.getDocumentElement().appendChild(entry);
    }
    
    public void addEntry(String Title, String username, String entryPassword) throws DBFormatException {

        addEntry(Title, "", username, entryPassword);
    }

    private String validateAttributeAndSanitise(String attribute) throws InvalidAttributeException {

        attribute = attribute.toLowerCase();

        if (!allowedAttributes.contains(attribute)) {

            throw new InvalidAttributeException(attribute + " is not a valid entry attribute.");
        }
        return attribute;
    }

    public void modifyEntry(int ID, String attribute, String newValue) throws InvalidAttributeException, DBFormatException {

        if (db == null) {
            throw new DBFormatException("Database not yet loaded.");
        }

        attribute = validateAttributeAndSanitise(attribute);

        getEntryNodeByID(ID).getAttributes().getNamedItem(attribute).setNodeValue(newValue);
    }

    private Node getEntryNodeByID(int ID) throws DBFormatException {

        if (db == null) {
            throw new DBFormatException("Database not yet loaded.");
        }

        int i = 0;
        Node currNode;
        NodeList nodes = db.getDocumentElement().getChildNodes();
        while ((currNode = nodes.item(i++)) != null) {

            if (Integer.parseInt(currNode.getAttributes().getNamedItem("id").getTextContent()) == ID) {

                return currNode;
            }
        }
        return null;
    }
    
    public HashSet<Integer> getIDsWhereMatches(String attribute, String value) throws InvalidAttributeException, DBFormatException {

        if (db == null) {
            throw new DBFormatException("Database not yet loaded.");
        }

        attribute = validateAttributeAndSanitise(attribute);

        HashSet<Integer> entryIDs = new HashSet<>();
        int i = 0;
        Node currNode;
        NodeList nodes = db.getDocumentElement().getChildNodes();
        while ((currNode = nodes.item(i++)) != null) {

            if (currNode.getAttributes().getNamedItem(attribute).getTextContent().equals(value)) {

                entryIDs.add(Integer.parseInt(currNode.getAttributes().getNamedItem("id").getTextContent()));
            }
        }
        return entryIDs;
    }

    public Entry getEntryByID(int ID) throws DBFormatException {
    
        Node entryNode = getEntryNodeByID(ID);
        if (entryNode == null) return null;
        NamedNodeMap attributes = entryNode.getAttributes();
        return new Entry(ID, attributes.getNamedItem("title").getTextContent(), attributes.getNamedItem("url").getTextContent(), attributes.getNamedItem("username").getTextContent(), attributes.getNamedItem("password").getTextContent());
    }

    public HashSet<Entry> getEntriesWhereMatches(String attribute, String value) throws InvalidAttributeException, DBFormatException {

        HashSet<Entry> entries = new HashSet<>();        

        HashSet<Integer> IDs = getIDsWhereMatches(attribute, value);
        for (int ID : IDs) {

            entries.add(getEntryByID(ID));
        }

        return entries;
    }

    public String getUsernameByID(int ID) throws DBFormatException {

        Node entryNode = getEntryNodeByID(ID);
        if (entryNode == null) return null;
        return entryNode.getAttributes().getNamedItem("username").getTextContent();
    }

    public String getPasswordByID(int ID) throws DBFormatException {

        Node entryNode = getEntryNodeByID(ID);
        if (entryNode == null) return null;
        return entryNode.getAttributes().getNamedItem("password").getTextContent();
    }

    public void createDB() {

        try {

            DocumentBuilderFactory dbf = DocumentBuilderFactory.newDefaultInstance();
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.newDocument();
            
            Element rootElement = doc.createElement("root");
            doc.appendChild(rootElement);
            rootElement.setAttribute("nextID", "1");

            this.db = doc;
        }
        catch (ParserConfigurationException e) {
            
            // we shouldnt ever really get here
        }
    }

    

    public void createFile() throws FileAccessException {

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
        catch (ParserConfigurationException e) {
        
            throw new FileAccessException("Could not write document to file.");
        }
    }

    private void writeDocument(Document doc) throws FileAccessException {

        try {

            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer t = tf.newTransformer();
            DOMSource source = new DOMSource(doc);
            StreamResult result = new StreamResult(new File(dbURL));
            t.transform(source, result);
        }
        catch (TransformerException e) {

            throw new FileAccessException("Cannot write document to file.");
        }
    }

    private byte[] generateSalt() {

        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[16];
        random.nextBytes(bytes);
        return bytes;
    }
}