package com.user.userservice.services;

import com.user.userservice.dtos.UserDto;
import com.user.userservice.models.SessionStatus;
import org.springframework.http.ResponseEntity;

public interface AuthService {
    ResponseEntity<UserDto> login(String email, String password);
    ResponseEntity<Void> logout(String token, Long userId);

    UserDto signUp(String email, String password);
    SessionStatus validate(String token, Long userId);
}
