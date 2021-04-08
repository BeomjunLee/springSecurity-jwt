package security.jwt.exception;

public class RefreshTokenGrantTypeException extends RuntimeException {
    public RefreshTokenGrantTypeException(String message) {
        super(message);
    }
}
