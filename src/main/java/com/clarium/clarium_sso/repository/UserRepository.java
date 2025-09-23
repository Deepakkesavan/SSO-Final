package com.clarium.clarium_sso.repository;

import com.clarium.clarium_sso.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmail(String email);
    boolean existsByEmail(String email);
    boolean existsByUsername(String username);


    Optional<User> findByEmailIgnoreCase(String email);
//    Optional<User> findByEmailAndUsername(String email, String username);
}