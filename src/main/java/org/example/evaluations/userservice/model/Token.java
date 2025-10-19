package org.example.evaluations.userservice.model;

import jakarta.persistence.Entity;
import jakarta.persistence.ManyToOne;
import lombok.Getter;
import lombok.Setter;

import java.util.Date;

@Getter
@Setter
@Entity(name = "tokens")
public class Token extends BaseModel {
    private String tokenValue; // 255

    private Date expiryDate;

    @ManyToOne
    private User user;
}

// Token ---- User => M:1