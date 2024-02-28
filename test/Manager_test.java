import static org.junit.Assert.fail;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.util.HashSet;
import java.util.Iterator;


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
            Assert.assertEquals("sam", m.retrieveUsername(1));
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
            Assert.assertEquals("bananas", m.retrievePassword(1));
        } catch (Exception e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void getUsername_DBUninitialised() {

        Manager m = new Manager();
        Assert.assertThrows(DBFormatException.class, () -> m.retrieveUsername(1));
    }

    @Test
    public void getPassword_DBUninitialised() {

        Manager m = new Manager();
        Assert.assertThrows(DBFormatException.class, () -> m.retrievePassword(1));
    }

    @Test
    public void getUsername_DBEmpty() {

        try {
            Manager m = new Manager();
            m.createDB();
            Assert.assertNull(m.retrieveUsername(1));
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
            Assert.assertNull(m.retrievePassword(1));
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
            HashSet<Integer> entryIDs = m.getEntriesWhereMatches("URL", "samuelburke.xyz");
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
            Assert.assertThrows(InvalidAttributeException.class, () -> m.getEntriesWhereMatches("notanattribute", "samuelburke.xyz"));
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
            HashSet<Integer> entryIDs = m.getEntriesWhereMatches("Title", "MySite");
            Iterator<Integer> idIterator = entryIDs.iterator();
            Assert.assertEquals(2, entryIDs.size());
            Assert.assertEquals(1, (int)idIterator.next());
            Assert.assertEquals(3, (int)idIterator.next());
        }
        catch(EncryptionException | FileAccessException | DBFormatException | InvalidAttributeException e) {

            fail(e.getMessage());
        }
    }
}
