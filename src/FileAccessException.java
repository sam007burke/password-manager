public class FileAccessException extends Exception {
    
    public FileAccessException(String message) {
        super("Cannot access database file: " + message);
    }
}
