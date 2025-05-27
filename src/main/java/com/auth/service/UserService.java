package com.auth.service;

import com.auth.entity.Role;
import com.auth.entity.User;
import com.auth.exception.CustomException;
import com.auth.repository.UserRepository;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
public class UserService implements UserDetailsService {

    private final UserRepository userRepository;
    
    @PersistenceContext
    private EntityManager entityManager;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Kullanıcı bulunamadı: " + username));
    }

    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    public User getUserById(Long id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new CustomException("Kullanıcı bulunamadı. ID: " + id));
    }

    @Transactional
    public Role findOrCreateRole(String roleName) {
        List<Role> roles = entityManager.createQuery(
                "SELECT r FROM Role r WHERE r.name = :name", Role.class)
                .setParameter("name", roleName)
                .getResultList();
        
        if (!roles.isEmpty()) {
            return roles.get(0);
        }
        
        Role newRole = new Role();
        newRole.setName(roleName);
        entityManager.persist(newRole);
        return newRole;
    }
} 