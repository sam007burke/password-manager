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
}
