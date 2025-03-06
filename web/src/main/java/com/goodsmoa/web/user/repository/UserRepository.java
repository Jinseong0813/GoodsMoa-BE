
/*
* 1. 리포지터리(Repository)
-리포지터리는 데이터베이스와의 상호작용을 담당하는 부분이야.
 즉, 데이터베이스에서 데이터를 가져오고, 수정하고, 삭제하는 일을 해.
   리포지터리는 JPA에서 JpaRepository 같은 인터페이스를 상속받아서 제공되는
   기본적인 CRUD 기능을 사용할 수 있어.

    -핵심 포인트:
    데이터를 다루는 역할 (DB에 저장된 데이터를 가져오거나 수정하거나 삭제하는 작업)
    findByUsername()처럼 쿼리 메서드를 정의하여, DB에서 데이터를 가져오는 일을 한다.
    DB와의 연결을 관리하며, 데이터 액세스 레벨에서 필요한 모든 작업을 처리해.
* */






package com.goodsmoa.web.user.repository;



import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import com.goodsmoa.web.user.Entity.User;


@Repository // 이 클래스가 Repository임을 알려주는 어노테이션
public interface UserRepository extends JpaRepository<User,String> {


}
