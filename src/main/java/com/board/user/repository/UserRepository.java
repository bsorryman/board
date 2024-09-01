package com.board.user.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.board.user.domain.User;

public interface UserRepository extends JpaRepository<User, Integer>{

    User findByUsername(String username);

}
