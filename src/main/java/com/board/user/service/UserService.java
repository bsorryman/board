package com.board.user.service;

import org.springframework.stereotype.Service;

import com.board.user.domain.User;
import com.board.user.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserService {
   
    public final UserRepository userRepositoryImpl;
    
    public void saveUser(User user) {
        
        userRepositoryImpl.save(user);
    }
    
}
