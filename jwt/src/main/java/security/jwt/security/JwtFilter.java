package security.jwt.security;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import security.jwt.dto.response.LoginResponse;
import security.jwt.dto.response.Response;
import security.jwt.exception.TokenNotFoundException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.LocalDateTime;

@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

    public static final String AUTHORIZATION_HEADER = "Authorization";

    private final Logger log = LoggerFactory.getLogger(JwtFilter.class);
    private final JwtProvider jwtProvider;
    private final ObjectMapper objectMapper;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            String token = resolveToken(request);
            log.info(token + " 추출 완료");

            if (!StringUtils.hasText(token)) {
                log.info("jwt 토큰을 찾을수 없습니다");
                throw new TokenNotFoundException("토큰을 찾을 수 없습니다");
            }
            //jwt 에서 추출된 데이터가 들어있는 Authentication
            Authentication authentication = jwtProvider.getAuthentication(token);
            log.info(authentication + " Authentication 생성");

            //SecurityContextHolder 에 Authentication 를 세팅하기 때문에 @PreAuthorize 로 권한 파악가능
            SecurityContextHolder.getContext().setAuthentication(authentication);
            filterChain.doFilter(request, response);

        } catch (TokenNotFoundException e) {
            sendErrorResponse(response, "토큰을 찾을 수 없습니다");
        } catch (MalformedJwtException e) {
            sendErrorResponse(response, "손상된 토큰입니다");
        } catch (ExpiredJwtException e) {
            sendErrorResponse(response, "만료된 토큰입니다");
        } catch (UnsupportedJwtException e) {
            sendErrorResponse(response, "지원하지 않는 토큰입니다");
        } catch (SignatureException e) {
            sendErrorResponse(response, "시그니처 검증에 실패한 토큰입니다");
        }
    }

    /**
     * 헤더 token 추출
     * @param request HttpServletRequest
     * @return 헤더 토큰 추출 값
     */
    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(AUTHORIZATION_HEADER);
        if(StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer "))
            return bearerToken.substring(7);
        return null;
    }

    /**
     * jwt 예외처리 응답
     * @param response HttpServletResponse
     * @param message 응답 메세지
     * @throws IOException
     */
    private void sendErrorResponse(HttpServletResponse response, String message) throws IOException {
        response.setCharacterEncoding("utf-8");
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(objectMapper.writeValueAsString(Response.builder()
                .status(HttpStatus.UNAUTHORIZED.value())
                .message(message)
                .build()));
    }
}
