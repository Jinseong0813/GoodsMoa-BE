
/* jwt 토큰 페이로드에는 id, role, nickname 넣음 */

package security.provider;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import security.constrants.SecurityConstants;
import security.props.JwtProps;
import user.Entity.User;
import user.service.UserService;

import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.util.Date;

@Slf4j
@Component  // Spring의 빈(Bean)으로 등록하여, IoC(제어의 역전) 컨테이너에서 관리될 수 있도록 한다.
public class JwtProvider {

    @Autowired
    private JwtProps jwtProps; // JwtProps 클래스에서 시크릿키를 가져오는 역할

    @Autowired
    @Lazy // 여기서 @Lazy를 붙여주면 의존성 주입이 지연됨
    private UserService userService;

    /**
     * JWT 토큰을 생성하는 메서드
     *
     * @return 생성된 JWT 토큰
     */
    public String createToken(User user) {

        // JwtProps에서 시크릿 키를 가져온다.
        String secretKey = jwtProps.getSecretKey();

        // 시크릿 키가 null 또는 빈 문자열일 경우, 예외를 던지거나 기본값을 설정하는 것이 좋습니다.
        if (secretKey == null || secretKey.isEmpty()) {
            throw new IllegalStateException("비밀 키가 설정되지 않았습니다.");
        }

        // 가져온 시크릿 키를 바이트 배열로 변환
        byte[] signingKey = secretKey.getBytes();

        // HMAC-SHA 알고리즘에서 사용할 수 있는 형태로 시크릿 키를 변환 (HMAC-SHA 알고리즘을 사용해 서명을 생성)
        SecretKey shaKey = Keys.hmacShaKeyFor(signingKey);

        // 토큰 만료 시간 설정 (7일)
        int exp = 1000 * 60 * 60 * 24 * 7;  // 7일을 밀리초로 계산

        // JWT 토큰을 생성한다.
        String jwt = Jwts.builder()
                // 서명 생성: HMAC-SHA512 알고리즘을 사용하여 서명을 생성
                .signWith(shaKey, Jwts.SIG.HS512)
                // JWT 헤더에 "typ" 값 설정, "jwt"는 토큰의 유형을 나타냄
                .header().add("typ", SecurityConstants.TOKEN_TYPE)
                .and()
                // 토큰 만료 시간 설정
                .expiration(new Date(System.currentTimeMillis() + exp))
                // 페이로드에 사용자 정보를 담음
                //JWT에서 Long 타입을 그대로 claim()에 넣으면 문제가 될 수 있습니다
                //형변환 필요

                .claim("id", user.getId()) // 유저 ID
                .claim("email", user.getEmail()) // 이메일 (로그인 ID)
                .claim("nickname", user.getNickname()) // 닉네임
                .claim("role", user.getRole()) // 권한 (관리자 or 일반유저)
                // 모든 설정이 끝나면 최종적으로 JWT 토큰을 생성하고 반환
                .compact();

        // 생성된 JWT 토큰을 로그로 출력 (디버깅 용도)
        log.info("jwt:" + jwt);

        // 생성된 JWT 토큰을 반환
        return jwt;
        /* 인코딩되어 header.payload.signature 형태로 반환됨 */
    }
         /*
    디코딩된 헤더 예시:
     {
      "alg": "HS256",
     "typ": "jwt"
        }
    디코딩된 페이로드 예시
    {

    "username": "John Doe",
    "role": "ROLE_User"
    }
    디코딩된 서명 예시:
    gzyIHhTYql8DBD2e1e56qebHjiJmELPA9nY3UrtvIQY
    * */







    /**
     * JWT 토큰을 해석하여 사용자 인증 정보를 반환하는 메서드
     * @param authorization Authorization 헤더에서 받은 JWT 토큰
     * @return UsernamePasswordAuthenticationToken 인증 정보를 담은 객체
     */
    public UsernamePasswordAuthenticationToken getAuthenticationToken(String authorization) {

        // Authorization 헤더가 null 이거나 빈 값일 경우, 인증을 진행할 수 없으므로 null 반환
        if (authorization == null || authorization.length() == 0)
            return null;

        try {
            // JWT 토큰 추출: Authorization 헤더에서 "Bearer " 부분을 제거하고, 실제 JWT 토큰만 추출
            String jwt = authorization.replace("Bearer ", "");
            log.info("jwt:" + jwt);

            // JWT 파싱(해석) (서명 검증 및 페이로드 추출)
            Jws<Claims> parsedToken = Jwts.parser()
                    .setSigningKey(getShaKey()) // 시크릿키를 사용해 서명 검증
                    .build()
                    .parseClaimsJws(jwt);



            log.info("parsedToken:" + parsedToken);



            // 사용자 id
            String id =  parsedToken.getBody().get("id").toString();
            // 회원 권한
            Boolean role = (Boolean) parsedToken.getBody().get("role");

            String nickname= (String) parsedToken.getBody().get("nickname");

            // 해당 유저의 정보 담기 위해 Users 객체 생성
            User user = new User();
            user.setId(id);
            user.setRole(role);
            user.setNickname(nickname);


            // UsernamePasswordAuthenticationToken을 생성하여 인증 정보를 반환
            //첫 번째 매개변수 (users): 인증된 사용자의 상세 정보.
            //두 번째 매개변수 (null): 사용자의 비밀번호인데, 이미 인증이 끝난 후라 비밀번호는 필요하지 않아서 null을 넣었어.
            //세 번째 매개변수 (userDetails.getAuthorities()): 사용자의 권한 목록.
            // getAuthorities()는 UserDetails 객체에(여기선 customuser)서 사용자 권한들을 반환하는 메서드
            // Spring Security 인증 객체 생성 (권한이 필요 없으면 null 전달)
            return new UsernamePasswordAuthenticationToken(user, null, null);

        } catch (ExpiredJwtException exception) {
            log.warn("만료된 JWT 토큰을 파싱하려는 시도: {}", exception.getMessage());
        } catch (UnsupportedJwtException exception) {
            log.warn("지원되지 않는 JWT 토큰을 파싱하려는 시도: {}", exception.getMessage());
        } catch (MalformedJwtException exception) {
            log.warn("잘못된 형식의 JWT 토큰을 파싱하려는 시도: {}", exception.getMessage());
        } catch (IllegalArgumentException exception) {
            log.warn("빈 JWT 토큰을 파싱하려는 시도: {}", exception.getMessage());
        }

        // 예외가 발생하면 null을 반환하여 인증을 실패시킨다.
        return null;
    }



    /* 토큰이 유효기간이 올바른지 검증하기(만료토큰은 ㄴㄴ)
    인증 전에 토큰의 만료 여부만 빠르게 체크하고 싶은 상황에서 사용함
    * 아직 유효하면 true, 아니면 false 반환*/
    public boolean validateToken(String jwt) {

        try{
            Jws<Claims> claims= Jwts.parser().verifyWith(getShaKey()).build().parseSignedClaims(jwt);
            Date expiration = claims.getBody().getExpiration();
            log.info("만료기간:" + expiration.toString());
            //만료날짜인 expiration과 현재오늘 날짜 비교하기
            //날짜a.after(날짜b): 날짜a가 날짜b보다 더 뒤에 있으면 true
            boolean result=expiration.after(new Date()); //만료안됐으면 true임
            return result;

        } catch(ExpiredJwtException exception){
            log.error("토큰 만료");
        }

        catch (JwtException e) {
            log.error("토큰 손상");

        }catch (NullPointerException e) {
            log.error("토큰 없음");


        }catch( Exception e) {

        }
        return false;


    }





    /**
     * 실제 사용할 수 있는 시크릿키를 반환하는 메서드
     * @return 시크릿키
     */
    public SecretKey getShaKey() {
        // JwtProps에서 시크릿 키를 가져온다.
        String secretKey = jwtProps.getSecretKey();



        // 바이트 배열로 변환하여 HMAC-SHA 알고리즘에서 사용할 수 있는 SecretKey 객체를 생성한다.
        byte[] signingKey = secretKey.getBytes();
        return Keys.hmacShaKeyFor(signingKey); // SecretKey 객체 반환
    }
}
