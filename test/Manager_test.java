import static org.junit.Assert.fail;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;


public class Manager_test {


    @Before
    public void setUpDB() {

        try {

            Manager m = new Manager();
            m.enterPassword("bananas");
            m.setDbURL("myFiles/test.pdb");
            m.createDB();
            m.createFile();
            m.addEntry("samuelburke.xyz", "sam", "bananas");
            m.addEntry("google.com", "sam@gmail.com", "myGooglePassword123");
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
            Assert.assertEquals("sam", m.retrieveUsername("samuelburke.xyz"));
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
            Assert.assertEquals("bananas", m.retrievePassword("samuelburke.xyz"));
        } catch (Exception e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void getUsername_DBUninitialised() {

        Manager m = new Manager();
        Assert.assertThrows(DBFormatException.class, () -> m.retrieveUsername("samuelburke.xyz"));
    }

    @Test
    public void getPassword_DBUninitialised() {

        Manager m = new Manager();
        Assert.assertThrows(DBFormatException.class, () -> m.retrievePassword("samuelburke.xyz"));
    }

    @Test
    public void getUsername_DBEmpty() {

        try {
            Manager m = new Manager();
            m.createDB();
            Assert.assertNull(m.retrieveUsername("samuelburke.xyz"));
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
            Assert.assertNull(m.retrievePassword("samuelburke.xyz"));
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
}
