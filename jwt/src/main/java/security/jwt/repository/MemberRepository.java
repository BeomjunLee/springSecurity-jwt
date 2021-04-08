package security.jwt.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import security.jwt.domain.Member;

import java.util.Optional;

public interface MemberRepository extends JpaRepository<Member, Long> {

    Optional<Member> findMemberByUsername(String username);

    Optional<Member> findMemberByUsernameAndRefreshToken(String username, String refreshToken);
}
