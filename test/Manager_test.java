import static org.junit.Assert.fail;

import org.hamcrest.MatcherAssert;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.theories.suppliers.TestedOn;

import java.util.HashSet;
import java.util.Iterator;

import javax.print.attribute.HashAttributeSet;


public class Manager_test {


    @Before
    public void setUpDB() {

        try {

            Manager m = new Manager();
            m.enterPassword("bananas");
            m.setDbURL("myFiles/test.pdb");
            m.createDB();
            m.createFile();
            m.addEntry("MySite", "samuelburke.xyz", "sam", "bananas");
            m.addEntry("Google", "sam@gmail.com", "myGooglePassword123");
            m.addEntry("MySite", "samuelburke.co.uk", "sam", "anotherpassword");
            m.encryptDB();

        } catch (Exception e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void getUsername() {

        try {

            Manager m = new Manager();
            m.enterPassword("bananas");
            m.setDbURL("myFiles/test.pdb");
            m.decryptDB();
            Assert.assertEquals("sam", m.getUsernameByID(1));
        } catch (Exception e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void getPassword() {

        try {

            Manager m = new Manager();
            m.enterPassword("bananas");
            m.setDbURL("myFiles/test.pdb");
            m.decryptDB();
            Assert.assertEquals("bananas", m.getPasswordByID(1));
        } catch (Exception e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void getUsername_DBUninitialised() {

        Manager m = new Manager();
        Assert.assertThrows(DBFormatException.class, () -> m.getUsernameByID(1));
    }

    @Test
    public void getPassword_DBUninitialised() {

        Manager m = new Manager();
        Assert.assertThrows(DBFormatException.class, () -> m.getPasswordByID(1));
    }

    @Test
    public void getUsername_DBEmpty() {

        try {
            Manager m = new Manager();
            m.createDB();
            Assert.assertNull(m.getUsernameByID(1));
        }
        catch (DBFormatException e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void getPassword_DBEmpty() {

        try {
            Manager m = new Manager();
            m.createDB();
            Assert.assertNull(m.getPasswordByID(1));
        }
        catch (DBFormatException e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void saltingProvidesDiffCipherTexts() {

        try {

            Manager m = new Manager();
            m.enterPassword("bananas");
            m.setDbURL("myFiles/test-identical.pdb");
            m.createDB();
            m.createFile();
            m.addEntry("samuelburke.xyz", "sam", "bananas");
            m.addEntry("google.com", "sam@gmail.com", "myGooglePassword123");
            m.encryptDB();

            Manager o = new Manager();
            o.setDbURL("myFiles/test.pdb");
            Assert.assertNotEquals(m.getEncryptedContents(), o.getEncryptedContents());

        } catch (Exception e) {
            fail(e.getMessage());
        }

    }

    @Test
    public void getIDsByValidAttribute() {

        try {

            Manager m = new Manager();
            m.enterPassword("bananas");
            m.setDbURL("myFiles/test.pdb");
            m.decryptDB();
            HashSet<Integer> entryIDs = m.getIDsWhereMatches("URL", "samuelburke.xyz");
            Assert.assertEquals(1, entryIDs.size());
            Assert.assertEquals(1, (int)entryIDs.iterator().next());
        }
        catch(EncryptionException | FileAccessException | DBFormatException | InvalidAttributeException e) {

            fail(e.getMessage());
        }
    }

    @Test
    public void getIDsByInvalidAttribute() {

        try {

            Manager m = new Manager();
            m.enterPassword("bananas");
            m.setDbURL("myFiles/test.pdb");
            m.decryptDB();
            Assert.assertThrows(InvalidAttributeException.class, () -> m.getIDsWhereMatches("notanattribute", "samuelburke.xyz"));
        }
        catch(EncryptionException | FileAccessException | DBFormatException e) {

            fail(e.getMessage());
        }
    }

    @Test
    public void getMultipleIDsByAttribute() {

        try {

            Manager m = new Manager();
            m.enterPassword("bananas");
            m.setDbURL("myFiles/test.pdb");
            m.decryptDB();
            HashSet<Integer> entryIDs = m.getIDsWhereMatches("Title", "MySite");
            Iterator<Integer> idIterator = entryIDs.iterator();
            Assert.assertEquals(2, entryIDs.size());
            Assert.assertEquals(1, (int)idIterator.next());
            Assert.assertEquals(3, (int)idIterator.next());
        }
        catch(EncryptionException | FileAccessException | DBFormatException | InvalidAttributeException e) {

            fail(e.getMessage());
        }
    }

    @Test
    public void getEntryByID_1() {

        try {

            Manager m = new Manager();
            m.enterPassword("bananas");
            m.setDbURL("myFiles/test.pdb");
            m.decryptDB();
            Entry e = m.getEntryByID(1);
            Assert.assertNotNull(e);
            Assert.assertEquals(1, e.getID());
            Assert.assertEquals("MySite", e.getTitle());
            Assert.assertEquals("samuelburke.xyz", e.getURL());
            Assert.assertEquals("sam", e.getUsername());
            Assert.assertEquals("bananas", e.getPassword());
        }
        catch(EncryptionException | FileAccessException | DBFormatException e) {

            fail(e.getMessage());
        }
    }

    @Test
    public void getEntryByID_NoID() {

        try {

            Manager m = new Manager();
            m.enterPassword("bananas");
            m.setDbURL("myFiles/test.pdb");
            m.decryptDB();
            Entry e = m.getEntryByID(10);
            Assert.assertNull(e);
        }
        catch(EncryptionException | FileAccessException | DBFormatException e) {

            fail(e.getMessage());
        }
    }

    @Test
    public void getEntriesByTitle_existsMultiple() {

        try {

            Manager m = new Manager();
            m.enterPassword("bananas");
            m.setDbURL("myFiles/test.pdb");
            m.decryptDB();
            HashSet<Entry> es = m.getEntriesWhereMatches("title", "MySite");
            Iterator<Entry> esi = es.iterator();
            Assert.assertEquals(2, es.size());
            HashSet<Integer> ids = new HashSet<>();
            ids.add(esi.next().getID());
            ids.add(esi.next().getID());
            Assert.assertTrue(ids.contains(1));
            Assert.assertTrue(ids.contains(3));
        }
        catch(EncryptionException | FileAccessException | DBFormatException e) {

            fail(e.getMessage());
        }
    }

    @Test
    public void getEntriesByTitle_existsOne() {

        try {

            Manager m = new Manager();
            m.enterPassword("bananas");
            m.setDbURL("myFiles/test.pdb");
            m.decryptDB();
            HashSet<Entry> es = m.getEntriesWhereMatches("title", "Google");
            Assert.assertEquals(1, es.size());
            Iterator<Entry> esi = es.iterator();
            Assert.assertEquals(2, esi.next().getID());
        }
        catch(EncryptionException | FileAccessException | DBFormatException e) {

            fail(e.getMessage());
        }
    }

    @Test
    public void getEntriesByTitle_notExists() {

        try {

            Manager m = new Manager();
            m.enterPassword("bananas");
            m.setDbURL("myFiles/test.pdb");
            m.decryptDB();
            HashSet<Entry> es = m.getEntriesWhereMatches("title", "NotATitle");
            Assert.assertEquals(0, es.size());
        }
        catch(EncryptionException | FileAccessException | DBFormatException e) {

            fail(e.getMessage());
        }
    }

    @Test
    public void getEntriesByInvalidAttribute() {

        try {

            Manager m = new Manager();
            m.enterPassword("bananas");
            m.setDbURL("myFiles/test.pdb");
            m.decryptDB();
            Assert.assertThrows(InvalidAttributeException.class, () -> m.getEntriesWhereMatches("titleName", "Google"));
        }
        catch(EncryptionException | FileAccessException | DBFormatException e) {

            fail(e.getMessage());
        }
    }

    @Test
    public void modifyEntry_valid_password() {

        try {

            Manager m = new Manager();
            m.enterPassword("bananas");
            m.setDbURL("myFiles/test.pdb");
            m.decryptDB();
            m.modifyEntry(2, "password", "Ch@ngedP@55");
            Assert.assertEquals("Ch@ngedP@55", m.getPasswordByID(2));
        }
        catch(EncryptionException | FileAccessException | DBFormatException e) {

            fail(e.getMessage());
        }
    }
}
