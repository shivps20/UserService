package org.example.evaluations.userservice.services;

import org.example.evaluations.userservice.model.Token;
import org.example.evaluations.userservice.model.User;

public interface IUserService {
    User signup(String name, String email, String password);

    Token login(String email, String password);

    User validateToken(String token);
}
