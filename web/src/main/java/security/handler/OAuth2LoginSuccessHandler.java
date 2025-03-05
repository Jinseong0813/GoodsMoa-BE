//✅ 로그인 성공 시 JWT를 클라이언트에 전달하는 핸들러!
//✔ 로그인 성공하면 JWT를 생성하고 응답헤더로 반환
//✔ 클라이언트가 JWT를 받아서 저장하고 API 호출할 때 사용

package security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import security.provider.JwtProvider;
import user.Entity.User;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

import security.constrants.SecurityConstants;
@Component
public class OAuth2LoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtProvider jwtProvider;

    public OAuth2LoginSuccessHandler(JwtProvider jwtProvider) {
        this.jwtProvider = jwtProvider;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        User user = (User) oAuth2User;

        // JWT 발급
        String jwtToken = jwtProvider.createToken(user);

        // ✅ JWT를 Authorization 헤더에 추가
        response.setHeader(SecurityConstants.TOKEN_HEADER, SecurityConstants.TOKEN_PREFIX + jwtToken);
    }
}
