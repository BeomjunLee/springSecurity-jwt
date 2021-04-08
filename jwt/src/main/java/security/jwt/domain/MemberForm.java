package security.jwt.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@AllArgsConstructor
public class MemberForm {
    private String username;
    private String password;
    private String name;
}
