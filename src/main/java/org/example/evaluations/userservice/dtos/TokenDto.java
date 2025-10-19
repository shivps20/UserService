package org.example.evaluations.userservice.dtos;

import lombok.Data;
import org.example.evaluations.userservice.model.Token;

@Data
public class TokenDto {
    private String tokenValue;

    public static TokenDto from(Token token) {
        if (token == null) {
            return null;
        }

        TokenDto tokenDto = new TokenDto();
        tokenDto.setTokenValue(token.getTokenValue());
        return tokenDto;
    }
}
