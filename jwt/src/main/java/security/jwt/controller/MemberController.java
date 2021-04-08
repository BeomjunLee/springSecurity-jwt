package security.jwt.controller;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import security.jwt.domain.MemberForm;
import security.jwt.dto.LoginDto;
import security.jwt.dto.response.LoginResponse;
import security.jwt.dto.response.Response;
import security.jwt.security.JwtProvider;
import security.jwt.service.MemberService;

import java.security.Principal;

@Controller
@RequestMapping("/api")
@RequiredArgsConstructor
public class MemberController {

    private final Logger log = LoggerFactory.getLogger(MemberController.class);
    private final MemberService memberService;
    private final JwtProvider jwtProvider;
    private final AuthenticationManager authenticationManager;

    @PostMapping("/members")
    @ResponseStatus(HttpStatus.CREATED)
    public Response signUp(MemberForm form) {

        memberService.signUp(form);

        return Response.builder()
                    .status(HttpStatus.CREATED.value())
                    .message("회원 가입 성공").build();
    }

    @PostMapping("/login")
    public ResponseEntity login(@RequestBody LoginDto loginDto) {

        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword());

        //아이디 체크는 Authentication 에 사용자 입력 아이디, 비번을 넣어줘야지 작동
        Authentication authentication = authenticationManager.authenticate(authenticationToken);
        log.info(authentication + " 로그인 처리 authentication");

        //jwt 생성
        String jwt = jwtProvider.generateToken(authentication, false);
        
        LoginResponse response = LoginResponse.builder()
                .status(HttpStatus.OK.value())
                .message("로그인 성공")
                .accessToken(jwt)
                .build();
        return ResponseEntity.ok(response);
    }

    @PreAuthorize("hasRole('ROLE_USER')")
    @GetMapping("/test")
    public ResponseEntity test() {
        Response response = Response.builder()
                .status(HttpStatus.OK.value())
                .message("테스트 성공")
                .build();
        return ResponseEntity.ok(response);
    }
}
