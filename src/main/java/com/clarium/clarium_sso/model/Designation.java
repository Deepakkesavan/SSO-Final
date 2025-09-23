package com.clarium.clarium_sso.model;

import jakarta.persistence.*;
import lombok.Data;
import lombok.ToString;
import java.util.List;
import java.util.UUID;

@Entity
@Table(name = "Designation", schema = "dbo")
@Data
@ToString(exclude = "workInfos") // Prevent circular reference
public class Designation {

    @Id
    @Column(name = "DesgID")
    private Integer designationId;

    @Column(name = "Desg")
    private String designation;

    @Column(name = "Id", columnDefinition = "uniqueidentifier")
    private UUID id;

    // One-to-Many relationship with WorkInfo
    @OneToMany(mappedBy = "designation", fetch = FetchType.LAZY)
    private List<WorkInfo> workInfos;
}