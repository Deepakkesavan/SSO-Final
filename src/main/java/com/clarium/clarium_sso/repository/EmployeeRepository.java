package com.clarium.clarium_sso.repository;

import com.clarium.clarium_sso.model.Employee;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface EmployeeRepository extends JpaRepository<Employee, Integer> {

    // Find email exists or not
    Boolean existsByEmail(String email);

    Optional<Employee> findByEmail(String email);
}
