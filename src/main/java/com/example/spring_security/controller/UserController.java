package com.example.spring_security.controller;

import com.example.spring_security.domain.dto.UserJoinRequest;
import com.example.spring_security.domain.dto.UserLoginRequest;
import com.example.spring_security.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @PostMapping("/join")
    public ResponseEntity<String> join(@RequestBody UserJoinRequest dto) {

        userService.join(dto.getUsername(), dto.getPassword());

        return ResponseEntity.ok().body("회원가입 성공");
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody UserLoginRequest dto) {

        String token = userService.login(dto.getUsername(), dto.getPassword());
        return ResponseEntity.ok().body(token);
    }
}
