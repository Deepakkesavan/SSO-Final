package com.clarium.clarium_sso.repository;

import com.clarium.clarium_sso.model.Otp;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface OtpRepository extends JpaRepository<Otp, UUID> {
    Optional<Otp> findByEmail(String email);
    void deleteByEmail(String email);
}
