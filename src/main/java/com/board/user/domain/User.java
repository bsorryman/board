package com.board.user.domain;

import java.util.ArrayList;
import java.util.Collection;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "tb_user")
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Getter
public class User implements UserDetails{
    /**
     * 
     */
    private static final long serialVersionUID = 1L;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "idx", nullable = false)
    private int idx;
    
    @Column(name = "username", nullable = true)
    private String username;
    
    @Column(name = "password", nullable = true)
    private String password;
    
    @Column(name = "nickname", nullable = true)
    private String nickname;
    
    @Column(name = "email", nullable = true)
    private String email;
    
    @Column(name = "picture", nullable = true)
    private String picture;
    
    @Column(name = "role", nullable = true)
    private String role;
    
    @Column(name = "sns", nullable = true)
    private String sns;
    
    @Column(name = "created_at", nullable = true)
    private String createdAt;
    
    @Column(name = "modified_at", nullable = true)
    private String modifiedAt;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> authorities = new ArrayList<>();

        for(String role : role.split(",")){
            authorities.add(new SimpleGrantedAuthority(role));
        }
        
        return authorities;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
    
    public void updatePassword(String password) {
        this.password = password;
    }
}
