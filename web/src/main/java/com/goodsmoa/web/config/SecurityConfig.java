

/*
* SecurityConfig.java는?
-Spring Security를 사용해 보안 규칙(인증과 인가)을 설정하는 클래스야.
    URL 접근 권한, JWT 토큰 필터 추가, 로그인/로그아웃 처리 등을 여기서 지정해.
-JWT 필터를 추가해서, 들어오는 요청의 토큰을 확인하고 인증을 처리하는 로직을 포함할 수도 있어.
-인증(Authentication): 누가 접근하는지 확인하는 것.
-인가(Authorization): 접근 권한이 있는지 확인하는 것.
*
* */


package com.goodsmoa.web.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import com.goodsmoa.web.security.filter.JwtRequestFilter;
import com.goodsmoa.web.security.provider.JwtProvider;

import java.util.Arrays;

import com.goodsmoa.web.security.service.CustomOAuth2UserService;
import com.goodsmoa.web.security.handler.OAuth2LoginSuccessHandler;

@Configuration
@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class SecurityConfig {

    //✅ 카카오 서비스 객체 주입
    @Autowired
    private CustomOAuth2UserService customOAuth2UserService; // ✅ 객체(Bean)로 주입

    //✅ 카카오 로그인 성공 핸들러 객체 주입
    @Autowired
    private OAuth2LoginSuccessHandler oAuth2LoginSuccessHandler; // ✅ 성공 핸들러 객체 주입

    // 비밀번호 암호화 빈 등록
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    @Autowired
    private JwtProvider jwtProvider;

    // AuthenticationManager를 빈으로 등록
    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
        AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
        return authenticationManagerBuilder.build();
    }

    // CORS 설정을 위한 CorsConfigurationSource 빈
    // ✅ CORS 설정 (React 프론트엔드 요청 허용)
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        // ✅ 모든 도메인(Origin) 허용 → React Native에서 API 요청 가능
        configuration.addAllowedOriginPattern("*");

        // ✅ 허용할 HTTP 메서드
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));

        // ✅ 허용할 요청 헤더
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type"));

        // ✅ 프론트엔드에서 응답 헤더에서 Authorization 확인 가능하도록 설정
        configuration.setExposedHeaders(Arrays.asList("Authorization"));

        // ✅ 쿠키 및 인증 정보 포함 허용
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }


    // HTTP 보안 설정을 위한 메서드
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        // 폼 로그인 비활성화
        http.formLogin(login -> login.disable());

        // HTTP 기본 인증 비활성화
        http.httpBasic(basic -> basic.disable());

        // CSRF 비활성화
        http.csrf(csrf -> csrf.disable());

        // 세션 비활성화
        http.sessionManagement(management -> management.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        // 이미 등록된 authenticationManager 빈을 사용
        AuthenticationManager authenticationManager = authenticationManager(http);

        // 필터 설정
        http.addFilterBefore(new JwtRequestFilter(authenticationManager, jwtProvider), UsernamePasswordAuthenticationFilter.class);

        // CORS 설정 적용
        http.cors(cors -> cors.configurationSource(corsConfigurationSource())); // CorsConfigurationSource 적용


        // ✅ URL별 접근 권한 설정
        http.authorizeHttpRequests(auth -> auth
                .requestMatchers("/oauth2/**", "/login/**").permitAll() // ✅ 카카오 로그인 허용
                .anyRequest().authenticated() // ✅ 그 외 모든 요청은 인증 필요
        );

        // ✅ OAuth2 로그인 설정 (카카오 로그인)
        http.oauth2Login(oauth2 -> oauth2
                .userInfoEndpoint(userInfo -> userInfo
                        // CustomOAuth2UserService: 🔹 로그인시 카카오 로그인 사용자 정보 처리하고 jwt 발급해줌
                        .userService(customOAuth2UserService)
                )
                .successHandler(oAuth2LoginSuccessHandler) // 🔹 로그인 성공 시 JWT 발급
        );


        // ✅ JWT 필터 추가 (모든 요청 전에 실행)
 /*       📌 JwtRequestFilter가 하는 역할
✅ 모든 요청마다 Authorization 헤더를 확인하고, JWT가 유효한지 검사함
✅ JWT가 유효하면 SecurityContextHolder에 사용자 인증 정보 저장
✅ 이제 인증된 사용자만 API 요청을 할 수 있음!*/
        http.addFilterBefore(new JwtRequestFilter(authenticationManager(http), jwtProvider), UsernamePasswordAuthenticationFilter.class);


        return http.build();
    }
}
