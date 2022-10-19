package com.maro.security.web;

import com.maro.security.service.AuthService;
import com.maro.security.token.TokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RequiredArgsConstructor
@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;

    @PostMapping("/login")
    public String login(@RequestBody Map<String, String> request){
        return authService.login(request.get("userId"));
    }
    @GetMapping("/test")
    public void test(){

    }
}
