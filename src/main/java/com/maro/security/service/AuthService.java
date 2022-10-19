package com.maro.security.service;

import com.maro.security.token.TokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@Service
public class AuthService {

    private final TokenProvider tokenProvider;

    public String login(String userId){
        String accessToken = tokenProvider.createAccessToken(userId);
        String refreshToken = tokenProvider.createRefreshToken(userId);

        return accessToken;
    }
}
