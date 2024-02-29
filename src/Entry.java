/**
 * This is used to get entries, not modify them (modfications should be done directly)
 */
public class Entry {
    
    private int ID;
    private String title;
    private String URL;
    private String username;
    private String password;

    public Entry(int ID, String title, String URL, String username, String password) {

        this.ID = ID;
        this.title = title;
        this. URL = URL;
        this.username = username;
        this.password = password;
    }

    public int getID() {
        return ID;
    }

    public String getTitle() {
        return title;
    }
    
    public String getURL() {
        return URL;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }
}
