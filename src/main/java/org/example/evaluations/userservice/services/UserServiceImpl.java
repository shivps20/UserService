package org.example.evaluations.userservice.services;

import org.apache.commons.lang3.RandomStringUtils;
import org.example.evaluations.userservice.exceptions.InvalidTokenException;
import org.example.evaluations.userservice.exceptions.PasswordMismatchException;
import org.example.evaluations.userservice.model.Role;
import org.example.evaluations.userservice.model.Token;
import org.example.evaluations.userservice.model.User;

import org.example.evaluations.userservice.repositories.RoleRepository;
import org.example.evaluations.userservice.repositories.TokenRepository;
import org.example.evaluations.userservice.repositories.UserRepository;
import org.example.evaluations.userservice.util.JwtTokenProvider;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.Optional;

@Service
public class UserServiceImpl implements IUserService{

    private UserRepository userRepository;
    private BCryptPasswordEncoder bCryptPasswordEncoder;
    private RoleRepository roleRepository;
    private TokenRepository tokenRepository;

    /**
     * Before the Construction injunction of BCryptPasswordEncoder, ensure that its Bean is already defined,
     * becasue BCryptPasswordEncoder, is not automatically registered — Spring doesn’t know where to get it from.
     *
     * Spring’s Inversion of Control (IoC) container only knows how to inject beans that it manages.
     * To make something autowirable (like BCryptPasswordEncoder), it must be registered as a bean in the Spring context.
     * Otherwise, Spring doesn’t know how to construct or supply it when building your service
     *
     */

    public UserServiceImpl(UserRepository  userRepository,
                           BCryptPasswordEncoder  bCryptPasswordEncoder,
                           RoleRepository roleRepository,
                           TokenRepository tokenRepository)
    {
        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.roleRepository = roleRepository;
        this.tokenRepository = tokenRepository;
    }

    @Override
    public User signup(String name, String email, String password) {

        //1. First check if the user already exists, if exists redirect this to the login page
        Optional<User> optionalUser = userRepository.findByEmail(email);
        if(optionalUser.isPresent())
        {
            //redirect to login page
            return optionalUser.get();
        }

        //2. If doesn't exists then create the user
        User user = new User();
        user.setName(name);
        user.setEmail(email);
//        user.setPassword(password); //Don't use this, rather encrypt the password and then store
        user.setPassword(bCryptPasswordEncoder.encode(password));

        // Initialize the roles list before adding roles
        user.setRoles(new ArrayList<>());

        //Assign the role to the user - By default use Buyer role
        Optional<Role> optionalRole = roleRepository.findByValue("BUYER");
        if (optionalRole.isPresent()) {
            user.getRoles().add(optionalRole.get());
        } else {
            throw new RuntimeException("Default BUYER role not found");
        }

        userRepository.save(user); //Save to DB

        return user;
    }



    @Override
    public Token login(String email, String password) throws PasswordMismatchException {
        //1. Check if the user exists or not
        Optional<User> optionalUser = userRepository.findByEmail(email);

        if(optionalUser.isEmpty())
        {
            return null; //redirect to the signup page
        }

        //2. Validate the Provided Password
        if(!bCryptPasswordEncoder.matches(password,optionalUser.get().getPassword()))
        {
            throw new PasswordMismatchException("Invalid Password. Enter correct password.");
        }

        //3. Login Successful. Generate login token
        Token token = new Token();
        token.setUser(optionalUser.get());
        //Random string of 128 chracters
        token.setTokenValue(RandomStringUtils.randomAlphanumeric(128));

        //Set the Expiry date e.g. 30 days from generation date
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DATE, 30);
        Date expirationDate = calendar.getTime();
        token.setExpiryDate(expirationDate);

        return tokenRepository.save(token);
    }


    @Override
    public String loginWithJWT(String email, String password) throws PasswordMismatchException {
        //1. Check if the user exists or not
        Optional<User> optionalUser = userRepository.findByEmail(email);

        if(optionalUser.isEmpty())
        {
            return null; //redirect to the signup page
        }

        //2. Validate the Provided Password
        if(!bCryptPasswordEncoder.matches(password,optionalUser.get().getPassword()))
        {
            throw new PasswordMismatchException("Invalid Password. Enter correct password.");
        }

        //3. Login Successful. Generate JWT token using JJWT library
        String token = JwtTokenProvider.generateToken("shiv@example.com", "BUYER");


        return token;
    }


    @Override
    public User validateToken(String token) throws InvalidTokenException{
        /**
         * 1. Check if there are tokens in the database whose expiry is greater than current date
         * 2. If exists, check if the token is expired or not
         * 3. If not expired, return the user associated with the token
         */

        //1+2 => Check Token validity
        Optional<Token> optionalToken = tokenRepository.findByTokenValueAndExpiryDateAfter(token, new Date());
        if(optionalToken.isEmpty())
        {
            //Token is invalid or expired
            throw new InvalidTokenException("Token is Invalid. Login again"); //Redirect to login page
        }

        //3. Token is valid. Return the user associated with the token
        return optionalToken.get().getUser();
    }
}
