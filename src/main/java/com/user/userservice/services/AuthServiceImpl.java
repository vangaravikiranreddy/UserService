package com.user.userservice.services;

import com.user.userservice.dtos.UserDto;
import com.user.userservice.models.Role;
import com.user.userservice.models.Session;
import com.user.userservice.models.SessionStatus;
import com.user.userservice.models.User;
import com.user.userservice.repositories.SessionRepository;
import com.user.userservice.repositories.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.MacAlgorithm;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.time.DateUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.MultiValueMapAdapter;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.*;


@Service
public class AuthServiceImpl implements AuthService{

    private final UserRepository userRepository;

    private SessionRepository sessionRepository;

    private BCryptPasswordEncoder bCryptPasswordEncoder;

    public AuthServiceImpl(UserRepository userRepository,
                           BCryptPasswordEncoder bCryptPasswordEncoder,
                           SessionRepository sessionRepository) {
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.userRepository = userRepository;
        this.sessionRepository = sessionRepository;
    }

    @Override
    public ResponseEntity<UserDto> login(String email, String password) {
        Optional<User> optionalUser = userRepository.findByEmail(email);
        if (optionalUser.isEmpty()) {
            return null;
        }
        User user = optionalUser.get();
        if (!bCryptPasswordEncoder.matches(password,user.getPassword())) {
            throw new RuntimeException("Incorrect Password");
        }
        if (user.getSessions().size() == 2) {
            throw new RuntimeException("User Limit exceeded");
        }
        UserDto userDto = UserDto.from(user);

        // Create a test key suitable for the desired HMAC-SHA algorithm:
        MacAlgorithm alg = Jwts.SIG.HS256; //or HS384 or HS256
        SecretKey key = alg.key().build();

        //JSON -> Key : Value
        Map<String, Object> jsonMap = new HashMap<>();
        jsonMap.put("email", user.getEmail());
        jsonMap.put("roles", List.of(user.getRoles()));
        jsonMap.put("createdAt", new Date());
        jsonMap.put("expiryAt", DateUtils.addDays(new Date(), 3));

        // Create the compact JWS:
        String jws = Jwts.builder()
                .claims(jsonMap)
                .signWith(key, alg)
                .compact();

        Session session = new Session();
        session.setToken(jws);
        session.setUser(user);
        session.setSessionStatus(SessionStatus.ACTIVE);
        session.setExpirngAt(DateUtils.addDays(new Date(), 1));
        sessionRepository.save(session);

        MultiValueMapAdapter<String, String> headers = new MultiValueMapAdapter<>(new HashMap<>());
        headers.add(HttpHeaders.SET_COOKIE, "auth-token="+jws);

        ResponseEntity<UserDto> response = new ResponseEntity<>(userDto, headers, HttpStatus.OK);
        return response;
    }

    @Override
    public ResponseEntity<Void> logout(String token, Long userId) {
        Optional<Session> optionalSession = sessionRepository.findByTokenAndUser_Id(token, userId);

        if (optionalSession.isEmpty()) {
            return null;
        }

        Session session = optionalSession.get();
        session.setSessionStatus(SessionStatus.ENDED);
        sessionRepository.save(session);

        return ResponseEntity.ok().build();
    }


    @Override
    public UserDto signUp(String email, String password) {
        User user = new User();
        user.setEmail(email);
        user.setPassword(bCryptPasswordEncoder.encode(password));
        User userSaved = userRepository.save(user);
        return UserDto.from(userSaved);
    }

    @Override
    public SessionStatus validate(String token, Long userId) {
        Optional<Session> optionalSession = sessionRepository.findByTokenAndUser_Id(token, userId);
        if (optionalSession.isEmpty()) {
            return null;
        }
        Session session = optionalSession.get();
        if(!session.getSessionStatus().equals(SessionStatus.ACTIVE)) {
          return SessionStatus.ENDED;
        }
//        Date currentTime = new Date();
//        if (session.getExpirngAt().before(currentTime)) {
//            return SessionStatus.ENDED;
//        }
        // JWT Decoding
        Jws<Claims> claimsJws = Jwts.parser().build().parseSignedClaims(token);
        String email = (String)claimsJws.getPayload().get("email");
        List<Role> roles = (List<Role>) claimsJws.getPayload().get("roles");
        Date createdAt = (Date) claimsJws.getPayload().get("createdAt");
        System.out.println(email);
        return session.getSessionStatus();
    }

}
