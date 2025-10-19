package org.example.evaluations.userservice.controllers;

import org.example.evaluations.userservice.dtos.LoginRequestDto;
import org.example.evaluations.userservice.dtos.SignUpRequestDto;
import org.example.evaluations.userservice.dtos.TokenDto;
import org.example.evaluations.userservice.dtos.UserDto;
import org.example.evaluations.userservice.model.Token;
import org.example.evaluations.userservice.model.User;
import org.example.evaluations.userservice.services.IUserService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/users")
public class UserController {

    private IUserService userService;

    //Constructor based injunction instead of Autowire
    public UserController(IUserService userService) {
        this.userService = userService;
    }

    @PostMapping("/signup")
    public UserDto signup(@RequestBody SignUpRequestDto requestDto) {
        User user = userService.signup(
                requestDto.getName(),
                requestDto.getEmail(),
                requestDto.getPassword()
        );

        return UserDto.from(user);
    }

    @PostMapping("/login")
    public TokenDto login(@RequestBody LoginRequestDto requestDto) {
        Token token = userService.login(requestDto.getEmail(), requestDto.getPassword());

        return TokenDto.from(token);
    }

    @GetMapping("/validate/{tokenValue}")
    public UserDto validateToken(@PathVariable("tokenValue") String tokenValue) {
        return null;
    }
}
