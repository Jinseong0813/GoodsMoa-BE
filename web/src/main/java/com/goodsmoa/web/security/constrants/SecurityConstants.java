/*
* <SecurityConstants.java>

-보안 관련 **상수들(예: JWT 토큰 앞에 붙이는 접두사, HTTP 헤더 이름, 만료 시간 등)**을 모아둔 파일이야.
-( 해당 클래스는 Spring Security 및 JWT 관련 상수를 정의한 상수 클래스입니다.)
-즉 "중요한 보안 값들을 한 곳에 정리해놓은 상수집"이야.
* - 여러 곳에서 반복적으로 사용할 수 있어서 관리하기 편해!

*
*
* */


package com.goodsmoa.web.security.constrants;

/* jwt 토큰은 http 헤더중 authorization이라는 헤더에 담김! */
/**
 * HTTP
 *     headers : {
 *			Authorization : Bearer ${jwt}
 * 	   }
 */

/*final(상수화): 불변(변경 불가), 상속 금지, 오버라이딩 금지.
static: 객체 생성 없이 클래스에서 직접 사용할 수 있는 변수/메서드.*/
public final class SecurityConstants {

    // JWT 토큰을 HTTP 헤더에서 식별하는 데 사용되는 헤더 이름
    public static final String TOKEN_HEADER = "Authorization";

    // JWT 토큰의 접두사. 일반적으로 "Bearer " 다음에 실제 토큰이 옵니다.
    public static final String TOKEN_PREFIX = "Bearer ";

    // JWT 토큰의 타입을 나타내는 상수
    public static final String TOKEN_TYPE = "JWT";

    //로그인 경로
    public static final String LOGIN_URL="/login";

    // 이 클래스를 final로 선언하여 상속을 방지하고, 상수만을 정의하도록 만듭니다.
}
