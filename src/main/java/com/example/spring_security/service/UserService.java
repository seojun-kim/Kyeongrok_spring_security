package com.example.spring_security.service;

import com.example.spring_security.domain.User;
import com.example.spring_security.exception.AppException;
import com.example.spring_security.exception.ErrorCode;
import com.example.spring_security.repository.UserRepository;
import com.example.spring_security.utils.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder encoder;

    @Value("${jwt.token.secret}")
    private String key;

    private Long expireTimeMs = 1000 * 60 * 60L;

    public String join(String username, String password) {

        userRepository.findByUsername(username)
                .ifPresent(user -> {
                    throw new AppException(ErrorCode.USERNAME_DUPLICATED, username + "는 이미 있음");
                });

        User user = User.builder()
                .username(username)
                .password(encoder.encode(password))
                .build();

        userRepository.save(user);

        return "success";
    }

    public String login(String username, String password) {

        User user = userRepository.findByUsername(username).orElseThrow(() -> new AppException(ErrorCode.USERNAME_NOT_FOUND, username + "이 없습니다"));

        if(!encoder.matches(password, user.getPassword())) {
            throw new AppException(ErrorCode.INVALID_PASSWORD, "패스워드를 잘못 입력 했습니다.");
        }

        String token = JwtUtil.createToken(username, key, expireTimeMs);

        return token;
    }
}
