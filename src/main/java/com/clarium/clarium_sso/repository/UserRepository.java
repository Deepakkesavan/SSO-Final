package com.clarium.clarium_sso.repository;

import com.clarium.clarium_sso.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.util.List;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmail(String email);
    Optional<User> findByUsername(String empId);
    boolean existsByEmail(String email);
    boolean existsByUsername(String username);


    Optional<User> findByEmailIgnoreCase(String email);
//    Optional<User> findByEmailAndUsername(String email, String username);

    @Query("SELECT u FROM User u WHERE u.exitDate <= :targetDate")
    List<User> findUsersToDeleteByExitDate(@Param("targetDate") LocalDate targetDate);


    @Modifying
    @Transactional
    @Query("DELETE FROM User u WHERE u.exitDate <= :targetDate")
    void deleteUsersOlderThan90Days(@Param("targetDate") LocalDate targetDate);

}