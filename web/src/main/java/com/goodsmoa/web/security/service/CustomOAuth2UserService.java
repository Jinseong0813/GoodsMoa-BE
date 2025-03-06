package com.goodsmoa.web.security.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.stereotype.Service;
import com.goodsmoa.web.user.Entity.User;
import com.goodsmoa.web.user.repository.UserRepository;
import com.goodsmoa.web.security.provider.JwtProvider;

import jakarta.servlet.http.HttpServletResponse;

import java.util.Collections;
import java.util.Map;
import java.util.Optional;

import com.goodsmoa.web.security.constrants.SecurityConstants;

@Slf4j
@Service
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final UserRepository userRepository;
    private final JwtProvider jwtProvider;
    private final HttpServletResponse response; // ✅ 헤더에 추가하기 위해 주입

    public CustomOAuth2UserService(UserRepository userRepository, JwtProvider jwtProvider, HttpServletResponse response) {
        this.userRepository = userRepository;
        this.jwtProvider = jwtProvider;
        this.response = response;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        log.info("카카오 로그인 사작");
        // ✅ 카카오에서 사용자 정보 가져오기
        OAuth2User oAuth2User = new org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService().loadUser(userRequest);

        // ✅ 카카오가 반환한 사용자 정보 파싱
        Map<String, Object> attributes = oAuth2User.getAttributes();
        Map<String, Object> kakaoAccount = (Map<String, Object>) attributes.get("kakao_account");
        Map<String, Object> profile = (Map<String, Object>) kakaoAccount.get("profile");

        // ✅ 사용자 정보 추출
        String id = attributes.get("id").toString(); // 카카오 유저 ID
        String nickname = (String) profile.get("nickname"); // 닉네임

        // ✅ DB에서 사용자 조회 (없으면 저장)
        Optional<User> optionalUser = userRepository.findById(id);
        User user = optionalUser.orElseGet(() -> {
            User newUser = new User();
            newUser.setId(id);
            newUser.setNickname(nickname);
            newUser.setRole(false); // false = 일반 유저
            return userRepository.save(newUser);
        });




        // 권한 설정: 일반 사용자 권한 설정
        String role = user.getRole() ? "ROLE_ADMIN" : "ROLE_USER";  // true면 ROLE_ADMIN, false면 ROLE_USER
        SimpleGrantedAuthority authority = new SimpleGrantedAuthority(role);

// 사용자 정보를 Authentication 객체로 설정
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                user, null, Collections.singletonList(authority)  // 단일 권한 객체를 리스트로 설정
        );

// SecurityContext에 Authentication 객체 설정
        SecurityContextHolder.getContext().setAuthentication(authentication);



        // ✅ JWT 발급 (엑세스 + 리프레시)
        String accessToken = jwtProvider.createAccessToken(user);
        String refreshToken = jwtProvider.createRefreshToken(user);
        System.out.println("카카오 로그인 access 토큰 발급 완료! :"+accessToken);
        System.out.println("카카오 로그인 refresh 토큰 발급 완료! :"+refreshToken);

         // ✅ 리프레시 토큰을 DB에 저장 (선택적: 보안 강화를 위해 저장 가능)
        user.setRefreshtoken(refreshToken);
        userRepository.save(user);

        // ✅ JWT를 Authorization 헤더에 추가
        response.setHeader(SecurityConstants.TOKEN_HEADER, SecurityConstants.TOKEN_PREFIX + accessToken);
        response.setHeader("Refresh-Token", refreshToken);  // 🔹 리프레시 토큰도 추가


        // ✅ `CustomOAuth2User` 반환!
        return new CustomOAuth2User(user, attributes);
    }
}
