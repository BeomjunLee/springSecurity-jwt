## SpringSecurity-JWT-VERSION2 (AccessToken & RefreshToken)
version1 은 너무 복잡해 최적화 하였습니다.

### accessToken refreshToken 흐름
<img src="https://user-images.githubusercontent.com/69130921/114068215-a4ca2080-98d8-11eb-9bad-b8642a56fa01.png"><br><br>

### Security 로그인 처리 흐름
<img src="https://user-images.githubusercontent.com/69130921/114241552-47ab9900-99c4-11eb-8ccb-69765c8e0173.png"><br><br>

### 상세 설명 블로그 포스팅 보러가기
https://blog.naver.com/qjawnswkd/222304836903<br><br>

### JWT 예외처리
https://blog.naver.com/qjawnswkd/222303565093<br><br>

### Security 예외처리(AuthenticationEntryPoint, AccessDeniedHandler)
https://blog.naver.com/qjawnswkd/222303477758<br><br>

### AccessToken만 이용했을 경우
- AccessToken의 유효시간을 길게 설정하면 사용자는 자주 로그인을 할 필요가 없어서 편하겠지만 유효시간이 긴 만큼 악성사용자가 AccessToken을 탈취할수 있어 보안성이 떨어지게 됩니다<br><br>
- 반대로 AccessToken의 유효시간을 짧게 설정하면 보안성은 높아지나 사용자가 로그인을 자주 해야해서 편의성이 떨어지게 됩니다<br><br>
- JWT를 무효화시키면 되지않나 라고 생각할수 있지만 JWT는 설정한 유효시간이 지나야지만 만료될수 있습니다. 그전에 억지로 만료시킬수 없습니다<br><br><br>


### AccessToken과 RefreshToken을 둘다 이용했을 경우
- AccessToken의 유효시간을 짧게 설정하고 RefreshToken의 유효시간을 길게 설정합니다 그러면 AccessToken의 유효시간이 만료되어도 RefreshToken으로 사용자가 로그인을 하지 않고 AccessToken을 재급 받을수 있게됩니다<br>

- AccessToken의 유효시간이 짧아지므로 AccessToken이 탈취당해도 정보를 취득하는데 시간이 줄어들어서 보안성이 높아집니다<br><br>

### Login 요청
```json
POST http://localhost:8080/api/login
Content-Type: application/json

{"username":"test", "password":"1234"}
```

<br>

## Login 실패 응답
```json
POST http://localhost:8080/api/login

HTTP/1.1 400 
Content-Type: application/json;charset=UTF-8
Transfer-Encoding: chunked
Date: Thu, 08 Apr 2021 21:01:51 GMT
Connection: close

{
  "status": 400,
  "message": "로그인 실패"
}

```

<br>

### Login 응답
```json
POST http://localhost:8080/api/login

HTTP/1.1 200 
Content-Type: application/json;charset=UTF-8
Transfer-Encoding: chunked
Date: Thu, 08 Apr 2021 20:27:11 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{
  "status": 200,
  "message": "로그인 성공",
  "accessToken": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0Iiwicm9sZXMiOiJST0xFX0FETUlOLFJPTEVfVVNFUiIsImV4cCI6MTYxNzkxNDIzMX0.t83jPVJzIcjgRSIlV_OYIMMiixhwzrUmo9JZeg1yKPg",
  "expiredAt": "2021-04-09T05:37:11.114702",
  "refreshToken": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0Iiwicm9sZXMiOiJST0xFX0FETUlOLFJPTEVfVVNFUiIsImV4cCI6MTYxODAwMDAzMX0.XcRGzfpR6k0m-XcyvKOFJV6Q8XNpZwSpoOoo9h54U-g",
  "issuedAt": "2021-04-09T05:27:11.114735"
}
```

<br>

### Token 예외 응답
```json
HTTP/1.1 401 
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
Content-Type: application/json;charset=utf-8
Content-Length: 52
Date: Thu, 08 Apr 2021 20:36:08 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{
  "status": 401,
  "message": "토큰을 찾을 수 없습니다"
}

{
  "status": 401,
  "message": "손상된 토큰입니다"
}

{
  "status": 401,
  "message": "만료된 토큰입니다"
}

{
  "status": 401,
  "message": "지원하지 않는 토큰입니다"
}

{
  "status": 401,
  "message": "시그니처 검증에 실패한 토큰입니다"
}
```

<br>

### AccessToken 재발급 요청
```json
POST http://localhost:8080/api/refreshToken
Content-Type: application/json

{"grantType":"refreshToken", "refreshToken":"refreshToken 값"}
```

<br>

### AccessToken 재발급 응답
```json
POST http://localhost:8080/api/refreshToken

HTTP/1.1 200 
Content-Type: application/json;charset=UTF-8
Transfer-Encoding: chunked
Date: Thu, 08 Apr 2021 20:32:27 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{
  "status": 200,
  "message": "accessToken 재발급 성공",
  "accessToken": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0Iiwicm9sZXMiOiJST0xFX0FETUlOLFJPTEVfVVNFUiIsImV4cCI6MTYxNzkxNDU0N30.oODDqjalawd1Y5G6PJXdKeNeuSaiXUiR-B0tbq1fqZQ",
  "expiredAt": "2021-04-09T05:42:27.354446",
  "refreshToken": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0Iiwicm9sZXMiOiJST0xFX0FETUlOLFJPTEVfVVNFUiIsImV4cCI6MTYxODAwMDM0N30.AyWqKOipIuYHCENahzogmQCBkD_mlypXjZeuBZLvoEA",
  "issuedAt": "2021-04-09T05:32:27.354471"
}
```
