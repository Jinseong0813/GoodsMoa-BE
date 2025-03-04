package user.Entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.math.BigInteger;

@Entity
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Table(name = "user")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private BigInteger id;

    @Column(name = "name", length = 10)
    private String name;

    @Column(name = "password", length = 254, nullable = false)
    private String password;

    @Column(name = "email", length = 30, nullable = false)
    private String email;

    @Column(name = "phone_number", length = 15)
    private String phoneNumber;

    @Column(name = "nickname", length = 30, nullable = false)
    private String nickname;

    @Column(name = "image", length = 254)
    private String image;

    @Column(name = "content", length = 100)
    private String content;

    @Column(name = "Identity", columnDefinition = "TINYINT(1)")
    private Boolean identity;  // 기본값 X, NULL 허용

    @Column(name = "panelty")
    private Integer panelty;

    @Column(name = "status", nullable = false, columnDefinition = "TINYINT(1) DEFAULT 1")
    private Boolean status = true;

    @Column(name = "report_count", nullable = false, columnDefinition = "INT DEFAULT 0")
    private Integer reportCount = 0;

    @Column(name = "role", nullable = false, columnDefinition = "TINYINT(1) DEFAULT 0")
    private Boolean role = false;  // 0: 일반 유저, 1: 관리자
}
