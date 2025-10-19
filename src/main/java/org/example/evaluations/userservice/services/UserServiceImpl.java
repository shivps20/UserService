package org.example.evaluations.userservice.services;

import org.example.evaluations.userservice.model.Role;
import org.example.evaluations.userservice.model.Token;
import org.example.evaluations.userservice.model.User;

import org.example.evaluations.userservice.repositories.RoleRepository;
import org.example.evaluations.userservice.repositories.UserRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Optional;

@Service
public class UserServiceImpl implements IUserService{

    private UserRepository userRepository;
    private BCryptPasswordEncoder bCryptPasswordEncoder;
    private RoleRepository roleRepository;

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
                           RoleRepository roleRepository)
    {
        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.roleRepository = roleRepository;
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
    public Token login(String email, String password) {
        //1. Check if the user exists or not
        Optional<User> optionalUser = userRepository.findByEmail(email);

        if(optionalUser.isEmpty())
        {
            return null; //redirect to the signup page
        }

        if(bCryptPasswordEncoder.matches(password,optionalUser.get().getPassword()))
        {
//            throw new PasswordMis
        }

        return null;
    }

    @Override
    public User validateToken(String token) {
        return null;
    }
}
