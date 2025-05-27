package com.auth.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "users")
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String username;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(nullable = false)
    @JsonIgnore
    private String password;

    private boolean enabled = true;
    
    // Hesap kilitleme özellikleri
    @Column(name = "login_attempts")
    private int loginAttempts = 0;
    
    @Column(name = "last_login_attempt")
    private LocalDateTime lastLoginAttempt;
    
    @Column(name = "account_locked")
    private boolean accountLocked = false;
    
    @Column(name = "account_locked_until")
    private LocalDateTime accountLockedUntil;

    // 2FA özellikleri
    @Column(name = "mfa_enabled")
    private boolean mfaEnabled = false;
    
    @Column(name = "mfa_secret")
    @JsonIgnore
    private String mfaSecret;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "user_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    private Set<Role> roles = new HashSet<>();

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
    
    // Hesap kilitleme yönetimi
    public void incrementLoginAttempts() {
        this.loginAttempts++;
        this.lastLoginAttempt = LocalDateTime.now();
    }
    
    public void resetLoginAttempts() {
        this.loginAttempts = 0;
    }
    
    public void lockAccount(int lockDurationMinutes) {
        this.accountLocked = true;
        this.accountLockedUntil = LocalDateTime.now().plusMinutes(lockDurationMinutes);
    }
    
    public void unlockAccount() {
        this.accountLocked = false;
        this.accountLockedUntil = null;
        this.resetLoginAttempts();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role.getName()))
                .collect(Collectors.toList());
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        if (!accountLocked) return true;
        
        // Kilit süresi dolduysa otomatik kilit kaldırma
        if (accountLockedUntil != null && accountLockedUntil.isBefore(LocalDateTime.now())) {
            unlockAccount();
            return true;
        }
        
        return false;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }
} 