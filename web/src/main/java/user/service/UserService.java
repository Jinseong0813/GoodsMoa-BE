
/*
서비스(Service)
-서비스는 앱의 주요 기능을 처리하는 곳이야.
-예를 들어, 회원 가입이나 정보 수정 같은 작업을 여기서 해.
 -데이터베이스와 상호작용은 하지만, 직접 DB를 다루지 않고, 리포지터리를 통해 데이터를 가져오고 처리해.

  -핵심:
    앱의 기능을 처리 (회원 가입, 로그인 등)
    리포지터리를 호출해서 데이터를 가져옴
    DB와 직접 상호작용하지 않고, 데이터를 가공하고 로직을 처리함
   즉, 서비스는 리포지터리와 협력해서 실제 앱의 기능을 동작시키는 역할이야.
* */


/*
* <서비스-리포지토리 동작 예시>
사용자가 로그인하려고 할 때:
서비스는 사용자가 입력한 아이디로 해당 사용자가 존재하는지 확인하고, 로그인 로직을 처리.
리포지터리는 해당 아이디로 DB에서 사용자 정보를 찾아오는 역할.*/




package user.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import user.Entity.User;
import user.repository.UserRepository;

import java.math.BigInteger;

@Service // 이 클래스가 서비스임을 Spring에게 알려주는 어노테이션
public class UserService {

    @Autowired
    private UserRepository userRepository; // UsersRepository 의존성 주입


    // ID로 사용자 조회
    public User getUserById(String id) {
        // findById는 Optional을 반환하므로, orElseThrow()로 존재하지 않을 경우 예외 처리
        return userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("해당 ID의 사용자를 찾을 수 없습니다."));
    }
}
