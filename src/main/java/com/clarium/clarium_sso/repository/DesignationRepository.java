package com.clarium.clarium_sso.repository;

import com.clarium.clarium_sso.model.Designation;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;
import java.util.UUID;

public interface DesignationRepository extends JpaRepository<Designation, Integer> {

    Optional<Designation> findById(UUID id);

}
