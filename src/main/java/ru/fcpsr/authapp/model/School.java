package ru.fcpsr.authapp.model;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Entity
@NoArgsConstructor
public class School {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;
    @Lob
    private String title;
    private String subject;
    private String sport;
    @Lob
    private String address;
    private String phone;
    private float s;
    private float d;
}
