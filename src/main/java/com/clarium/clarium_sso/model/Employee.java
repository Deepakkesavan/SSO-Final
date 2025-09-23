package com.clarium.clarium_sso.model;

import jakarta.persistence.*;
import lombok.Data;
import lombok.ToString;

@Entity
@Table(name = "Employee", schema = "dbo")
@Data
@ToString(exclude = {"workInfo"}) // Prevent circular reference
public class Employee {

    @Id
    @Column(name = "EmpID")
    private Integer empId;

    @Column(name = "FirstName")
    private String firstName;

    @Column(name = "LastName")
    private String lastName;

    @Column(name = "Email")
    private String email;

    // One-to-One relationship with WorkInfo
    @OneToOne(mappedBy = "employee", fetch = FetchType.LAZY)
    private WorkInfo workInfo;

}


