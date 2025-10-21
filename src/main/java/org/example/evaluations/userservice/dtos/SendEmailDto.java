package org.example.evaluations.userservice.dtos;

import lombok.Data;

@Data
public class SendEmailDto {
    private String toEmail;
    private String subject;
    private String body;
}
