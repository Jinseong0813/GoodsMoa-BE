/*
*
* 5. JwtProps.java
-application.properties에 설정한 **JWT 관련 값들(시크릿 키, 만료 시간 등)을
     객체로 매핑(mapping)**해주는 역할을 해.
-쉽게 말하면 "설정 파일에 적어둔 JWT 정보들을 코드에서 쉽게 쓸 수 있도록 변환해주는 역할"이야.
*
* */




// 해당 클래스는 Spring Boot의 `@ConfigurationProperties`
// 어노테이션을 사용하여, application.properties(속성 설정 파일) 로부터
// JWT 관련 프로퍼티를 관리하는 프로퍼티 클래스입니다.
package com.goodsmoa.web.security.props;   // 이 파일이 속한 패키지. 보통 클래스의 경로를 나타냄.

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Data
@Component    // 이 클래스를 Spring Bean으로 등록하라는 어노테이션. 스프링 컨테이너에 객체가 자동으로 등록됨.
@ConfigurationProperties("aloha") // "aloha" 접두사로 시작하는 프로퍼티들을 이 클래스의 필드에 바인딩하겠다고 설정.
public class JwtProps {

    // application.properties 파일에서 정의된 'aloha.secret-key'와 매칭되는 값을 이 필드에 자동으로 주입
    // 주로 JWT 인증에서 사용할 시크릿 키 값을 저장할 필드
    // 예: aloha.secret-key=|+<T%0h;[G97|I$5Lr?h]}`8rUX.7;0gw@bF<R/|"-U0n:...
    private String secretKey; // `aloha.secret-key` 값을 여기에 자동으로 주입받음
}
