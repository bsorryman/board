package com.board.user.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import com.board.user.domain.User;
import com.board.user.service.UserDetailsServiceImpl;
import com.board.user.service.UserService;

import lombok.RequiredArgsConstructor;

@Controller
@RequestMapping("/user")
@RequiredArgsConstructor
public class UserController {
    private final PasswordEncoder passwordEncoder;

    private final UserService userService;
    private final UserDetailsServiceImpl userDetailsServiceImpl;
    
    @GetMapping("/login")
    public String getLoginPage() {
        
        return "user/login";
    }
    
    @GetMapping("/signup")
    public String getSignUpPage() {
        
        return "/user/signup";
    }
    
    @PostMapping("/signup")
    public String postSignUp(String username, String password, String email, String nickname) {
        
        try {
            String decodedPassword = passwordEncoder.encode(password);
    
            User user = User.builder()
                            .username(username)
                            .password(decodedPassword)
                            .email(email)
                            .nickname(nickname)
                            .role("user")
                            .build();
            
            user.updatePassword(decodedPassword);
            
            userService.saveUser(user);
            
            return "redirect:/user/login?notify=signup";
        } catch (Exception e) {
            
            return "redirect:/user/signup?notify=error";
        }
    }
    
    @PostMapping("/id-check")
    @ResponseBody
    public ResponseEntity<Void> postIdCheck(String username) {
        try {
            userDetailsServiceImpl.loadUserByUsername(username);
            
            // unfe 발생 X -> ID 중복 -> 409(CONFLICT)
            return new ResponseEntity<Void>(HttpStatus.CONFLICT);

        } catch (UsernameNotFoundException unfe) {
            
            // unfe 발생 -> ID 사용 가능
            return new ResponseEntity<Void>(HttpStatus.OK);
        } 
        catch (Exception e) {
            e.printStackTrace();
            
            return new ResponseEntity<Void>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }    
}
