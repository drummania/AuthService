package auth.exception;

public class AuthServiceException extends Exception {

    String errorMessage;

    public AuthServiceException(String errorMessage) {
        this.errorMessage = errorMessage;
    }

    public String getMessage() {
        return errorMessage;
    }
}
