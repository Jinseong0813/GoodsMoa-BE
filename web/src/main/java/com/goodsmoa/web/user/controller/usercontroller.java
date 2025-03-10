package com.goodsmoa.web.user.controller;


import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import com.goodsmoa.web.security.provider.JwtProvider;
import lombok.RequiredArgsConstructor;

@RestController // ✅ @Controller 대신 @RestController 사용 (JSON 응답)
@RequiredArgsConstructor // ✅ 생성자 주입 자동 적용 (Lombok)
public class usercontroller {

    private final JwtProvider jwtProvider; // ✅ JwtProvider를 주입받음




    //엑세스 토큰 재발급받는 api
    @PostMapping("/auth/refresh")
    public ResponseEntity<?> refreshAccessToken(@RequestHeader("Refresh-Token") String refreshToken) {
        if (refreshToken == null || refreshToken.isEmpty()) {
            return ResponseEntity.status(401).body("리프레시 토큰이 없습니다.");
        }

        String newAccessToken = jwtProvider.refreshAccessToken(refreshToken); // ✅ static 없이 사용!
        if (newAccessToken == null) {
            return ResponseEntity.status(401).body("유효하지 않은 리프레시 토큰입니다.");
        }

        return ResponseEntity.ok(newAccessToken);
    }
}
