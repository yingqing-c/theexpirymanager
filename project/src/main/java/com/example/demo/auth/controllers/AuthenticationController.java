package com.example.demo.auth.controllers;

import com.example.demo.auth.AuthenticationService;
import com.example.demo.auth.models.User;
import com.example.demo.auth.models.UserLoginRequest;
import com.example.demo.auth.security.jwt.JwtUtils;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@CrossOrigin(origins = "*")
@RestController
@RequestMapping("/auth")
public class AuthenticationController {

    private static final Logger logger = LoggerFactory.getLogger(AuthenticationController.class);

    @Autowired
    private AuthenticationService authenticationService;
    @Autowired
    private JwtUtils jwtService;

    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@RequestBody User user) {
        if (authenticationService.usernameExists(user.getUsername())) {
            return ResponseEntity.badRequest().body("{\"error\":\"Username already exists\"}");
        }

        if (authenticationService.emailExists(user.getEmail())) {
            return ResponseEntity.badRequest().body("{\"error\":\"Email already exists\"}");
        }

        boolean success = authenticationService.registerUser(user);

        if (success) {
            return ResponseEntity.ok("{\"msg\":\"Successfully created user!\"}");
        }
        return ResponseEntity.internalServerError().body("{\"error\": \"User registration failed\"}");
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(@Valid @RequestBody UserLoginRequest userReq) {
        if (authenticationService.checkLogin(userReq.getUsername(), userReq.getPassword())) {
            return ResponseEntity.ok(jwtService.generateJwtToken(userReq.getUsername()));
        }
        logger.info("User [" + userReq.getUsername() + "] attempted to login with invalid username/password");
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid username or password");
    }

}
