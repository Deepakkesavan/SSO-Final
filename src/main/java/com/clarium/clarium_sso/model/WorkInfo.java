package com.clarium.clarium_sso.model;

import jakarta.persistence.*;
import lombok.Data;
import lombok.ToString;
import java.util.UUID;

@Entity
@Table(name = "WorkInfo", schema = "dbo")
@Data
@ToString(exclude = {"employee", "designation"})
public class WorkInfo {

    @Id
    @Column(name = "EmpID")
    private Integer empId;

    @Column(name = "DesgnID", columnDefinition = "uniqueidentifier")
    private UUID desgnId;

    // One-to-One relationship with Employee (owner side)
    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "EmpID")
    @MapsId // empId is both PK and FK
    private Employee employee;


    // Many-to-One relationship with Designation
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "DesgnID", referencedColumnName = "Id",
            insertable = false, updatable = false)
    private Designation designation;
}

