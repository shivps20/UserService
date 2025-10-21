package org.example.evaluations.userservice.services;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import org.apache.commons.lang3.RandomStringUtils;
import org.example.evaluations.userservice.dtos.SendEmailDto;
import org.example.evaluations.userservice.exceptions.InvalidTokenException;
import org.example.evaluations.userservice.exceptions.PasswordMismatchException;
import org.example.evaluations.userservice.model.Role;
import org.example.evaluations.userservice.model.Token;
import org.example.evaluations.userservice.model.User;

import org.example.evaluations.userservice.repositories.RoleRepository;
import org.example.evaluations.userservice.repositories.TokenRepository;
import org.example.evaluations.userservice.repositories.UserRepository;
import org.example.evaluations.userservice.util.JwtTokenProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import javax.swing.text.html.Option;
import java.security.Key;
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
    private JwtTokenProvider jwtTokenProvider;
    private SecretKey SECRET_KEY;
    private KafkaTemplate<String, String> kafkaTemplate;
    private ObjectMapper objectMapper; //For JSON conversion/serialization

    @Value("${app.kafka.topics.email-events.name}")
    private String emailEventsTopic;



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
                           TokenRepository tokenRepository,
                           JwtTokenProvider jwtTokenProvider,
                           SecretKey secretKey,
                           KafkaTemplate<String, String> kafkaTemplate,
                           ObjectMapper objectMapper)
    {
        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.roleRepository = roleRepository;
        this.tokenRepository = tokenRepository;
        this.jwtTokenProvider = jwtTokenProvider;
        this.SECRET_KEY = secretKey;
        this.kafkaTemplate = kafkaTemplate;
        this.objectMapper = objectMapper;
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

        //Push an event to the Event Bus (e.g., Kafka) - User Created Event. To be consumed by Email service to send welcome email to the user
        pushSignupEventoMessageQueue(email, name);

        //Save to DB
        userRepository.save(user);

        return user;
    }

    /**
     * Push Signup Event to Message Queue (Kafka)
     */
    private void pushSignupEventoMessageQueue(String email, String name) {
        SendEmailDto sendEmailDto = new SendEmailDto();
        sendEmailDto.setToEmail(email);
        sendEmailDto.setSubject("Welcome to E-Commerce App");
        sendEmailDto.setBody("Hello " + name + ",\n\nThank you for registering with our E-Commerce application!\n\nBest Regards,\nE-Commerce Team");

        //Convert SendEmailDto to JSON string - Serialization
//        String emailEventJson = String.format("{\"toEmail\":\"%s\",\"subject\":\"%s\",\"body\":\"%s\"}",
//                sendEmailDto.getToEmail(),
//                sendEmailDto.getSubject(),
//                sendEmailDto.getBody()
//        );

        //Using Jackson ObjectMapper for JSON conversion - another way of serialization
        String emailEventJson = "";
        try {
            emailEventJson = objectMapper.writeValueAsString(sendEmailDto);
        } catch (Exception e) {
            e.printStackTrace();
        }
        //Publish the event to Kafka topic "email-topic"
        kafkaTemplate.send(emailEventsTopic, emailEventJson);
        System.out.println("Sending email event to email events topic: " + emailEventsTopic);
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
        String token = jwtTokenProvider.generateToken(email, "BUYER");


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

    @Override
    public User validateJWTToken(String jwtToken) throws InvalidTokenException {
        //assert Jwts.parser().verifyWith(key).build().parseSignedClaims(jws).getPayload().getSubject().equals("Joe");

        /**
         * 1. Create the Parser
         * 2. Get the Claims from the token and verify the token
         * 3. If token is valid, return the user associated with the token
         */
        JwtParser jwtParser = Jwts.parser().verifyWith(SECRET_KEY).build();
        Claims claims =  jwtParser.parseSignedClaims(jwtToken).getPayload();

        //Validate if the expiry time is valid
        Date expirationDate = claims.getExpiration();
        if(expirationDate.before(new Date()))
        {
            throw new InvalidTokenException("JWT Token is expired. Login again.");
        }

        //Validate the token by checking if the user exists in the database
        String email = claims.get("email").toString();
        Optional<User> optionalUser = userRepository.findByEmail(email);

        //Token is valid. Return the user associated with the token
        return optionalUser.get();
    }
}
