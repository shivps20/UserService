package org.example.evaluations.userservice.controllers;

import org.example.evaluations.userservice.dtos.LoginRequestDto;
import org.example.evaluations.userservice.dtos.SignUpRequestDto;
import org.example.evaluations.userservice.dtos.TokenDto;
import org.example.evaluations.userservice.dtos.UserDto;
import org.example.evaluations.userservice.exceptions.InvalidTokenException;
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
//    This method was using Token object, not a JWT token
//    @PostMapping("/login")
//    public ResponseEntity<TokenDto> login(@RequestBody LoginRequestDto requestDto) throws PasswordMismatchException {
//        Token token = userService.login(requestDto.getEmail(), requestDto.getPassword());
//
//        return ResponseEntity.ok(TokenDto.from(token));
//    }

    //This method is using JWT token for login
    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody LoginRequestDto requestDto)
            throws PasswordMismatchException {
        String jwtToken = userService.loginWithJWT(requestDto.getEmail(), requestDto.getPassword());

        return ResponseEntity.ok(jwtToken);
    }

    /**
     * http://localhost:8080/users/validate/iHCXwDlsleWFfwJawKo6RqAmtQ2ZMnj8uaF4nwLRVpdqQzCWH1EUg4c6gMlWtsVjqtio4DBXYpocm4pa67Hjst02Dsuv4FJyIl9PaQrVcMCi2r7LkLBINE7qSz1vpGgV
     * Method = Get
     * Headers: content-type: application/json
     */
    @GetMapping("/validate/{tokenValue}")
    public UserDto validateToken(@PathVariable("tokenValue") String tokenValue) {
        try {
//            User user = userService.validateToken(tokenValue);
            User user = userService.validateJWTToken(tokenValue);

            return UserDto.from(user);

        } catch(InvalidTokenException ite) {
            System.out.println("Invalid Token. Login again.");
            return null;
        }
    }
}
