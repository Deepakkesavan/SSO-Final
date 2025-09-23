package com.clarium.clarium_sso.repository;

import com.clarium.clarium_sso.model.WorkInfo;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface WorkInfoRepository extends JpaRepository<WorkInfo, Integer> {

    Optional<WorkInfo> findByEmpId(int empId);

}
