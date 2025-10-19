package org.example.evaluations.userservice.dtos;

import lombok.Data;

@Data
public class SignUpRequestDto {

    private String name;
    private String email;
    private String password;
}
