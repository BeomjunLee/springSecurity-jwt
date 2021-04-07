package security.jwt.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.Builder;
import lombok.Data;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class JwtProvider{

    private final String secretKey;
    private final long accessTokenValidMilliSeconds;
    private final long refreshTokenValidMilliSeconds;
    private Key key;

    public JwtProvider(@Value("${jwt.secretKey}") String secretKey,
                       @Value("${jwt.accessToken-valid-seconds}")long accessTokenValidSeconds,
                       @Value("${jwt.refreshToken-valid-seconds}")long refreshTokenValidSeconds) {
        this.secretKey = secretKey;
        this.accessTokenValidMilliSeconds = accessTokenValidSeconds * 1000;
        this.refreshTokenValidMilliSeconds = refreshTokenValidSeconds * 1000;
    }

    /**
     * secretKey 암호화 초기화
     */
//    @PostConstruct
//    protected void init() {
//        this.key = Keys.hmacShaKeyFor(this.secretKey.getBytes(StandardCharsets.UTF_8));
//    }

    /**
     * jwt 생성
     * @param authentication
     * @param isRefreshToken
     * @return
     */
    public String generateToken(Authentication authentication, boolean isRefreshToken) {
        String authorities = authentication.getAuthorities().stream()
                .map(grantedAuthority -> grantedAuthority.getAuthority())
                .collect(Collectors.joining(","));
        long now = (new Date()).getTime();
        Date validateDay;
        if(isRefreshToken) validateDay = new Date(now + this.refreshTokenValidMilliSeconds);
        else validateDay = new Date(now + this.accessTokenValidMilliSeconds);

        return Jwts.builder()
                .setSubject(authentication.getName())
                .claim("role_", authorities)
                .signWith(SignatureAlgorithm.HS256, secretKey.getBytes(StandardCharsets.UTF_8))
                .setExpiration(validateDay)
                .compact();
    }

    public Authentication getAuthentication(String token) {
        Claims claims = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();

        String[] roles = claims.get("role_").toString().split(",");
        List<SimpleGrantedAuthority> authorities = Arrays.stream(roles).map(role -> new SimpleGrantedAuthority(role)).collect(Collectors.toList());

        return new UsernamePasswordAuthenticationToken(claims.getSubject(), "", authorities);
    }

    /**
     * jwt 검증
     * @param response
     * @param token
     * @return
     * @throws IOException
     */
    public boolean validateToken(HttpServletResponse response, String token) throws IOException {
        try{
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            sendErrorResponse(response, "손상된 토큰입니다");
        } catch (ExpiredJwtException e) {
            sendErrorResponse(response, "만료된 토큰입니다");
        } catch (UnsupportedJwtException e) {
            sendErrorResponse(response, "유효하지 않은 토큰입니다");
        } catch (IllegalArgumentException e) {
            sendErrorResponse(response, "IllegalArgumentException");
        }
        return false;
    }


    /**
     * json 응답
     * @param response
     * @param message
     * @throws IOException
     */
    private void sendErrorResponse(HttpServletResponse response, String message) throws IOException {
        ObjectMapper objectMapper = new ObjectMapper();
        response.setStatus(HttpStatus.FORBIDDEN.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(objectMapper.writeValueAsString(ErrorResponse.builder()
                .status(HttpStatus.FORBIDDEN.value())
                .message(message)
                .build()));
    }

    @Data
    @Builder
    static class ErrorResponse{
        private int status;
        private String message;
    }
}
