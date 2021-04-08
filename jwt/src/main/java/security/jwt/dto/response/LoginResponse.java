package security.jwt.dto.response;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class LoginResponse {
    private int status;
    private String message;
    private String accessToken;
}
