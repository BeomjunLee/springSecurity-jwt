package security.jwt.service;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import security.jwt.domain.MemberRole;
import security.jwt.domain.Member;
import security.jwt.domain.MemberForm;
import security.jwt.dto.RefreshTokenDto;
import security.jwt.dto.response.LoginResponse;
import security.jwt.repository.MemberRepository;
import security.jwt.security.JwtProvider;
import security.jwt.exception.InvalidRefreshTokenException;
import security.jwt.exception.RefreshTokenGrantTypeException;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class MemberService implements UserDetailsService {

    private final Logger log = LoggerFactory.getLogger(MemberService.class);
    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtProvider jwtProvider;

    /**
     * 회원 가입
     * @param form
     */
    @Transactional
    public void signUp(MemberForm form) {
        Member member = Member.builder()
                .username(form.getUsername())
                .password(passwordEncoder.encode(form.getPassword()))
                .name(form.getName())
                .roles(Set.of(MemberRole.USER, MemberRole.ADMIN))
                .build();

        memberRepository.save(member);
    }

    /**
     * 로그인 요청 회원 찾기
     * @param username
     * @return
     * @throws UsernameNotFoundException
     */
    @Override
    public UserDetails loadUserByUsername(String username){
        log.info("로그인 요청 회원 찾기");
        Member member = memberRepository.findMemberByUsernameFetch(username)
                .orElseThrow(() -> new UsernameNotFoundException(username + " 아이디가 일치하지 않습니다"));

        return new User(member.getUsername(), member.getPassword(), authorities(member.getRoles()));
    }

    private Collection<? extends GrantedAuthority> authorities(Set<MemberRole> roles) {
        return roles.stream().map(role -> new SimpleGrantedAuthority("ROLE_" + role.name())).collect(Collectors.toList());
    }

    /**
     * 회원에게 refreshToken 저장
     * @param username
     * @return
     */
    @Transactional
    public void findMemberAndSaveRefreshToken(String username, String refreshToken) {
        Member member = memberRepository.findMemberByUsername(username).orElseThrow(() -> new UsernameNotFoundException(username + " 아이디가 일치하지 않습니다"));
        member.updateRefreshToken(refreshToken);
    }

    /**
     * refreshToken 으로 accessToken 재발급
     * @param refreshTokenDto
     * @return
     */
    @Transactional
    public LoginResponse refreshToken(RefreshTokenDto refreshTokenDto) {
        if (!refreshTokenDto.getGrantType().equals("refreshToken"))
            throw new RefreshTokenGrantTypeException("올바른 grantType 을 입력해주세요");

        Authentication authentication = jwtProvider.getAuthentication(refreshTokenDto.getRefreshToken());

        Member member = memberRepository.findMemberByUsernameAndRefreshToken(authentication.getName(), refreshTokenDto.getRefreshToken())
                .orElseThrow(() -> new InvalidRefreshTokenException("유효하지 않은 리프레시 토큰입니다"));
        //TODO InvalidRefreshTokenException 예외 Handler

        //jwt accessToken & refreshToken 발급
        String accessToken = jwtProvider.generateToken(authentication, false);
        String refreshToken = jwtProvider.generateToken(authentication, true);

        //refreshToken 저장 (refreshToken 은 한번 사용후 폐기)
        member.updateRefreshToken(refreshToken);

        LoginResponse response = LoginResponse.builder()
                .status(HttpStatus.OK.value())
                .message("accessToken 재발급 성공")
                .accessToken(accessToken)
                .expiredAt(LocalDateTime.now().plusSeconds(jwtProvider.getAccessTokenValidMilliSeconds()/1000))
                .refreshToken(refreshToken)
                .issuedAt(LocalDateTime.now())
                .build();
        return response;
    }
}
