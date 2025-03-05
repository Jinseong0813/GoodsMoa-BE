package user.Entity;

/*
 ID, 비밀번호, 이메일, 닉네임은 not null임
*
* */



import jakarta.persistence.*;
import lombok.*;

import java.math.BigInteger;

@Entity // JPA의 엔티티임을 선언
@Getter
@Setter
@NoArgsConstructor // 기본 생성자 자동 생성 (JPA에서 필수)
@AllArgsConstructor // 모든 필드를 포함하는 생성자 자동 생성
@Builder // 빌더 패턴을 사용하여 객체를 생성할 수 있도록 지원
@Table(name = "user") // 이 엔티티가 user 테이블과 매핑됨을 명시
public class User {

    @Id // 기본 키(PK) 지정
    @Column(name = "id", nullable = false) // 컬럼 이름 설정 및 NULL 값 허용 X
    private String id; // 유저 ID (기본 키)

    @Column(name = "name", length = 10) // 최대 길이 10 설정
    private String name; // 유저 이름

    @Column(name = "password", length = 254, nullable = false) // NULL 허용 X
    private String password; // 비밀번호

    @Column(name = "email", length = 30, nullable = false) // NULL 허용 X
    private String email; // 이메일 주소

    @Column(name = "phone_number", length = 15) // 최대 길이 15 설정
    private String phoneNumber; // 전화번호

    @Column(name = "nickname", length = 30, nullable = false) // NULL 허용 X
    private String nickname; // 닉네임

    @Column(name = "image", length = 254) // 최대 길이 254 설정
    private String image; // 프로필 이미지 URL

    @Column(name = "content", length = 100) // 최대 길이 100 설정
    private String content; // 유저 소개글

    @Column(name = "Identity", columnDefinition = "TINYINT(1)") // Boolean 타입의 작은 정수 컬럼
    private Boolean identity; // 본인 인증 여부 (기본값 없음, NULL 허용)

    @Column(name = "panelty") // 제재(패널티) 횟수 저장
    private Integer penalty; // 패널티 횟수

    @Column(name = "status", nullable = false, columnDefinition = "TINYINT(1) DEFAULT 1") // 기본값 1
    private Boolean status = true; // 계정 활성화 상태 (true: 활성, false: 비활성)

    @Column(name = "report_count", nullable = false, columnDefinition = "INT DEFAULT 0") // 기본값 0
    private Integer reportCount = 0; // 신고당한 횟수

    @Column(name = "role", nullable = false, columnDefinition = "TINYINT(1) DEFAULT 0") // 기본값 0
    private Boolean role = false; // 0: 일반 유저, 1: 관리자
}
