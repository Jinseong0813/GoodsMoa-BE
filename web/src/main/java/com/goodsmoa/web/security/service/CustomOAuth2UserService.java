
/*✅ 카카오에서 사용자 정보를 가져오고 새 유저면 회원가입/ 기존이면 로그인 진행하고 jwt 발급 !*/

package com.goodsmoa.web.security.service;

import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.stereotype.Service;
import com.goodsmoa.web.user.Entity.User;
import com.goodsmoa.web.user.repository.UserRepository;
import com.goodsmoa.web.security.provider.JwtProvider;
import java.util.Map;
import java.util.Optional;

@Service
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final UserRepository userRepository;
    private final JwtProvider jwtProvider;

    public CustomOAuth2UserService(UserRepository userRepository, JwtProvider jwtProvider) {
        this.userRepository = userRepository;
        this.jwtProvider = jwtProvider;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        // 카카오에서 사용자 정보 가져오기
        OAuth2User oAuth2User = new org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService().loadUser(userRequest);

        // 카카오가 반환한 사용자 정보
        Map<String, Object> attributes = oAuth2User.getAttributes();
        Map<String, Object> kakaoAccount = (Map<String, Object>) attributes.get("kakao_account");
        Map<String, Object> profile = (Map<String, Object>) kakaoAccount.get("profile");

        // 사용자 정보 추출
        String id = attributes.get("id").toString(); // 카카오 유저 ID
        String nickname = (String) profile.get("nickname"); // 닉네임

        // DB에서 사용자 조회 (없으면 저장)
        Optional<User> optionalUser = userRepository.findById(id);
        User user = optionalUser.orElseGet(() -> {
            User newUser = new User();
            newUser.setId(id);
            newUser.setNickname(nickname);
            newUser.setRole(false); //false가 일반유저
            return userRepository.save(newUser);
        });


        // JWT 발급
        //내 서버에서 만든 JWT
        //✅ 카카오에서 받아온 사용자 정보로 우리 서버에서 새로운 JWT를 발급하는 거야!
        String jwtToken = jwtProvider.createToken(user);

        // JWT를 attributes에 추가
        attributes.put("token", jwtToken);

        // ✅ `CustomOAuth2User` 반환!
        return new CustomOAuth2User(user, attributes);
    }
}
