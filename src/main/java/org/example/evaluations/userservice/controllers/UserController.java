package org.example.evaluations.userservice.controllers;

import org.example.evaluations.userservice.dtos.LoginRequestDto;
import org.example.evaluations.userservice.dtos.SignUpRequestDto;
import org.example.evaluations.userservice.dtos.TokenDto;
import org.example.evaluations.userservice.dtos.UserDto;
import org.example.evaluations.userservice.exceptions.PasswordMismatchException;
import org.example.evaluations.userservice.model.Token;
import org.example.evaluations.userservice.model.User;
import org.example.evaluations.userservice.services.IUserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/users")
public class UserController {

    private IUserService userService;

    //Constructor based injunction instead of Autowire
    public UserController(IUserService userService) {
        this.userService = userService;
    }


    /**
     * Sample JSON to be passed in the request body
     * {
     *   "name": "Shiv Singh",
     *   "email": "shiv@example.com",
     *   "password": "mypassword"
     * }
     *
     * Method = Post
     * http://localhost:8080/users/signup
     * Headers: content-type: application/json
     */
    @PostMapping("/signup")
    public ResponseEntity<UserDto> signup(@RequestBody SignUpRequestDto requestDto) {
        User user = userService.signup(
                requestDto.getName(),
                requestDto.getEmail(),
                requestDto.getPassword()
        );
        /**
         * We should not send the user object as is, because it contains sensitive information like password
         * So, we convert it to UserDto before sending it back to the client
         */
        return ResponseEntity.ok(UserDto.from(user));
    }

    /**
     * Sample JSON to be passed in the request body
     * {
     *   "email": "shrija@example.com",
     *   "password": "mypassword"
     * }
     * Method = Post
     * http://localhost:8080/users/login
     * Headers: content-type: application/json
     */
    @PostMapping("/login")
    public ResponseEntity<TokenDto> login(@RequestBody LoginRequestDto requestDto) throws PasswordMismatchException {
        Token token = userService.login(requestDto.getEmail(), requestDto.getPassword());

        return ResponseEntity.ok(TokenDto.from(token));
    }

    @GetMapping("/validate/{tokenValue}")
    public UserDto validateToken(@PathVariable("tokenValue") String tokenValue) {
        return null;
    }
}
