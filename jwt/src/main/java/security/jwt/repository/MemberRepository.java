package security.jwt.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import security.jwt.domain.Member;

import java.util.Optional;

public interface MemberRepository extends JpaRepository<Member, Long> {

    Optional<Member> findMemberByUsername(String username);

    @Query("select m from Member m join fetch m.roles where m.username = :username")
    Optional<Member> findMemberByUsernameFetch(@Param("username") String username);

    Optional<Member> findMemberByUsernameAndRefreshToken(String username, String refreshToken);

}
