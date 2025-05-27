# Spring Boot JWT Kimlik Doğrulama Sistemi

Bu proje, JWT token tabanlı kimlik doğrulama ile güvenli bir Spring Boot uygulamasını göstermektedir.

## Teknoloji Stack

- Java 17
- Spring Boot 3.2.0
- Spring Security
- JSON Web Token (JWT)
- MySQL
- Hibernate
- Maven

## Proje Yapısı

```
src/main/java/com/auth
  ├── controller/
  │   ├── AuthController.java
  │   └── UserController.java
  ├── service/
  │   ├── AuthService.java
  │   ├── UserService.java
  │   └── JwtService.java
  ├── repository/
  │   └── UserRepository.java
  ├── dto/
  │   ├── LoginRequest.java
  │   ├── RegisterRequest.java
  │   └── AuthResponse.java
  ├── entity/
  │   ├── User.java
  │   └── Role.java
  ├── security/
  │   ├── JwtAuthenticationFilter.java
  │   ├── SecurityConfig.java
  │   ├── TokenBlacklist.java
  │   └── RateLimitingFilter.java
  ├── exception/
  │   ├── GlobalExceptionHandler.java
  │   └── CustomException.java
  ├── audit/
  │   ├── AuditLogger.java
  │   └── SecurityEvent.java
  └── AuthApplication.java
```

## Güvenlik İyileştirmeleri ve Eksiklerin Giderilmesi

Sistemin mevcut hali güçlü bir temel sağlasa da, aşağıdaki güvenlik ve kod iyileştirmeleri yapılmıştır:

### 1. Token İptal Mekanizması

**Neden?** Kullanıcı çıkış yaptığında veya şifre değiştirdiğinde aktif JWT tokenların iptal edilmesi gerekir.

```java
@Service
public class TokenBlacklist {
    private final Set<String> blacklistedTokens = Collections.synchronizedSet(new HashSet<>());
    private final Map<String, Long> tokenExpirations = new ConcurrentHashMap<>();
    
    public void blacklistToken(String token, Date expiration) {
        blacklistedTokens.add(token);
        tokenExpirations.put(token, expiration.getTime());
    }
    
    public boolean isBlacklisted(String token) {
        return blacklistedTokens.contains(token);
    }
    
    @Scheduled(fixedRate = 3600000) // Her saat çalışır
    public void cleanupExpiredTokens() {
        long now = System.currentTimeMillis();
        tokenExpirations.entrySet().removeIf(entry -> entry.getValue() < now);
        blacklistedTokens.removeIf(token -> !tokenExpirations.containsKey(token));
    }
}
```

### 2. Token Yenileme Endpoint'i

**Neden?** Kullanıcıların sürekli yeniden giriş yapmadan token süresini uzatabilmeleri gerekir.

```java
@PostMapping("/refresh-token")
public ResponseEntity<AuthResponse> refreshToken(@RequestBody RefreshTokenRequest request) {
    return ResponseEntity.ok(authService.refreshToken(request.getRefreshToken()));
}
```

### 3. Brute Force Koruması ve Rate Limiting

**Neden?** Şifre deneme saldırılarına karşı koruma sağlar.

```java
@Component
@Order(1)
public class RateLimitingFilter extends OncePerRequestFilter {
    private final Map<String, Integer> requestCounts = new ConcurrentHashMap<>();
    private final Map<String, Long> blockedIps = new ConcurrentHashMap<>();
    
    private static final int MAX_REQUESTS = 20; // 10 dakikada maksimum 20 istek
    private static final int BLOCK_DURATION = 600000; // 10 dakika (milisaniye)
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                   FilterChain filterChain) throws ServletException, IOException {
        String ip = getClientIp(request);
        String path = request.getRequestURI();
        
        // Sadece auth endpointlerini sınırla
        if (path.startsWith("/api/auth/")) {
            if (isBlocked(ip)) {
                response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
                response.getWriter().write("Çok fazla istek gönderdiniz. Lütfen daha sonra tekrar deneyin.");
                return;
            }
            
            incrementRequestCount(ip);
            
            if (requestCounts.get(ip) > MAX_REQUESTS) {
                blockIp(ip);
                response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
                response.getWriter().write("Çok fazla istek gönderdiniz. Lütfen daha sonra tekrar deneyin.");
                return;
            }
        }
        
        filterChain.doFilter(request, response);
    }
    
    // Yardımcı metodlar...
}
```

### 4. Şifre Güvenliği Artırma

**Neden?** Güçlü şifre politikaları hesap ele geçirme saldırılarını zorlaştırır.

```java
public class PasswordValidator {
    private static final int MIN_LENGTH = 10;
    private static final int MAX_LENGTH = 128;
    private static final Pattern HAS_UPPER = Pattern.compile("[A-Z]");
    private static final Pattern HAS_LOWER = Pattern.compile("[a-z]");
    private static final Pattern HAS_NUMBER = Pattern.compile("\\d");
    private static final Pattern HAS_SPECIAL = Pattern.compile("[^A-Za-z0-9]");
    private static final List<String> COMMON_PASSWORDS = Arrays.asList("password", "123456", "qwerty");
    
    public static void validate(String password) {
        if (password.length() < MIN_LENGTH || password.length() > MAX_LENGTH) {
            throw new CustomException("Şifre 10-128 karakter arasında olmalıdır");
        }
        
        if (!HAS_UPPER.matcher(password).find()) {
            throw new CustomException("Şifre en az bir büyük harf içermelidir");
        }
        
        if (!HAS_LOWER.matcher(password).find()) {
            throw new CustomException("Şifre en az bir küçük harf içermelidir");
        }
        
        if (!HAS_NUMBER.matcher(password).find()) {
            throw new CustomException("Şifre en az bir rakam içermelidir");
        }
        
        if (!HAS_SPECIAL.matcher(password).find()) {
            throw new CustomException("Şifre en az bir özel karakter içermelidir");
        }
        
        if (COMMON_PASSWORDS.contains(password.toLowerCase())) {
            throw new CustomException("Bu şifre çok yaygın, lütfen daha güvenli bir şifre seçin");
        }
    }
}
```

### 5. Güvenlik Olay Günlüğü (Audit Logging)

**Neden?** Güvenlik olaylarının izlenmesi güvenlik ihlallerinin tespitini kolaylaştırır.

```java
@Service
public class AuditLogger {
    private static final Logger logger = LoggerFactory.getLogger("security-audit");
    
    public void logEvent(SecurityEvent event) {
        MDC.put("eventType", event.getType());
        MDC.put("username", event.getUsername());
        MDC.put("ip", event.getIp());
        
        logger.info(event.getMessage());
        
        MDC.clear();
    }
}
```

### 6. Güvenli Ortam Değişkenleri Kullanımı

**Neden?** Hassas bilgilerin doğrudan yapılandırma dosyalarında saklanması güvenlik riski oluşturur.

```properties
# application.properties - DEĞİŞTİRİLECEK
jwt.secret=${JWT_SECRET:defaultSecretKeyForDevEnvironmentOnlyDoNotUseInProduction}
jwt.expiration=${JWT_EXPIRATION:86400000}
jwt.refresh-expiration=${JWT_REFRESH_EXPIRATION:604800000}

# Veritabanı bilgileri ortam değişkenlerinden alınır
spring.datasource.url=${DB_URL:jdbc:mysql://localhost:3306/auth_db}
spring.datasource.username=${DB_USERNAME:root}
spring.datasource.password=${DB_PASSWORD:password}
```

### 7. İki Faktörlü Kimlik Doğrulama (2FA)

**Neden?** Tek bir kimlik bilgisinin ele geçirilmesi durumunda bile hesap güvenliğini sağlar.

```java
@Entity
public class User implements UserDetails {
    // Mevcut alanlar...
    
    private boolean mfaEnabled = false;
    private String mfaSecret;
    
    // Metodlar...
}

@Service
public class TwoFactorAuthService {
    private static final int CODE_DIGITS = 6;
    private static final int VALID_PERIOD = 30;
    
    public String generateSecretKey() {
        Base32 base32 = new Base32();
        byte[] buffer = new byte[20];
        new SecureRandom().nextBytes(buffer);
        return base32.encodeToString(buffer);
    }
    
    public String generateQrCodeUrl(String secret, String username) {
        return "otpauth://totp/AuthApp:" + username + 
               "?secret=" + secret + 
               "&issuer=AuthApp&algorithm=SHA1&digits=" + CODE_DIGITS + 
               "&period=" + VALID_PERIOD;
    }
    
    public boolean verifyCode(String secret, String code) {
        TimeBasedOneTimePasswordGenerator totp = new TimeBasedOneTimePasswordGenerator(
                Duration.ofSeconds(VALID_PERIOD));
        
        try {
            // TOTP doğrulama işlemi...
            return true; // veya false
        } catch (Exception e) {
            return false;
        }
    }
}
```

### 8. Kapsamlı Exception Handling

**Neden?** Güvenlik hatalarının doğru şekilde işlenmesi, hassas bilgilerin sızdırılmasını önler.

```java
@RestControllerAdvice
public class GlobalExceptionHandler {
    // Mevcut exception handler metodları...
    
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<Map<String, String>> handleAccessDeniedException() {
        Map<String, String> errorMap = new HashMap<>();
        errorMap.put("error", "Bu işlemi gerçekleştirmek için yetkiniz bulunmamaktadır");
        return new ResponseEntity<>(errorMap, HttpStatus.FORBIDDEN);
    }
    
    @ExceptionHandler(ExpiredJwtException.class)
    public ResponseEntity<Map<String, String>> handleExpiredJwtException() {
        Map<String, String> errorMap = new HashMap<>();
        errorMap.put("error", "Oturum süreniz dolmuştur, lütfen tekrar giriş yapın");
        return new ResponseEntity<>(errorMap, HttpStatus.UNAUTHORIZED);
    }
    
    @ExceptionHandler(InvalidJwtException.class)
    public ResponseEntity<Map<String, String>> handleInvalidJwtException() {
        Map<String, String> errorMap = new HashMap<>();
        errorMap.put("error", "Geçersiz kimlik doğrulama bilgisi");
        return new ResponseEntity<>(errorMap, HttpStatus.UNAUTHORIZED);
    }
}
```

### 9. CORS Yapılandırmasının İyileştirilmesi

**Neden?** CORS politikasının yanlış yapılandırılması cross-site saldırılarına izin verebilir.

```java
@Bean
public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration configuration = new CorsConfiguration();
    // Sadece belirli originlere izin ver
    configuration.setAllowedOrigins(Arrays.asList(
        "https://example.com", 
        "https://www.example.com"
    ));
    // Geliştirme ortamında localhost
    if (environment.acceptsProfiles(Profiles.of("dev"))) {
        configuration.addAllowedOrigin("http://localhost:3000");
    }
    configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
    configuration.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type"));
    configuration.setExposedHeaders(Collections.singletonList("Authorization"));
    configuration.setAllowCredentials(true);
    configuration.setMaxAge(3600L); // Preflight caching - 1 saat
    
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", configuration);
    return source;
}
```

### 10. Hassas Veri Koruması

**Neden?** Kullanıcı verilerinin sadece gerekli kısımlarının iletilmesi, veri sızıntısı riskini azaltır.

```java
// User entity'sinde:
@JsonIgnore
private String password;

@JsonIgnore
private String mfaSecret;

// AuthService.java'da:
public UserDTO getUserInfo(Long userId) {
    User user = userRepository.findById(userId)
        .orElseThrow(() -> new CustomException("Kullanıcı bulunamadı"));
    
    // Hassas verileri içermeyen DTO döndür
    return UserDTO.builder()
        .id(user.getId())
        .username(user.getUsername())
        .email(user.getEmail())
        .roles(user.getRoles().stream()
                .map(Role::getName)
                .collect(Collectors.toSet()))
        .mfaEnabled(user.isMfaEnabled())
        .createdAt(user.getCreatedAt())
        .build();
}
```

## Veritabanı Şeması

```sql
CREATE TABLE users (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(50) NOT NULL UNIQUE,
  email VARCHAR(100) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL,
  enabled BOOLEAN DEFAULT TRUE,
  mfa_enabled BOOLEAN DEFAULT FALSE,
  mfa_secret VARCHAR(255),
  login_attempts INT DEFAULT 0,
  last_login_attempt TIMESTAMP,
  account_locked BOOLEAN DEFAULT FALSE,
  account_locked_until TIMESTAMP,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE roles (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(20) NOT NULL UNIQUE
);

CREATE TABLE user_roles (
  user_id BIGINT NOT NULL,
  role_id BIGINT NOT NULL,
  PRIMARY KEY (user_id, role_id),
  FOREIGN KEY (user_id) REFERENCES users(id),
  FOREIGN KEY (role_id) REFERENCES roles(id)
);

CREATE TABLE password_history (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  user_id BIGINT NOT NULL,
  password VARCHAR(255) NOT NULL,
  change_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE security_audit_log (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  event_type VARCHAR(50) NOT NULL,
  username VARCHAR(50),
  ip_address VARCHAR(50),
  event_data JSON,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE blacklisted_tokens (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  token_hash VARCHAR(255) NOT NULL UNIQUE,
  expiry_date TIMESTAMP NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## Entity Sınıfları

**User.java**
```java
package com.auth.entity;

// ... mevcut importlar ...
import com.fasterxml.jackson.annotation.JsonIgnore;

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
```

**Role.java**
```java
package com.auth.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "roles")
public class Role {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(length = 20, unique = true)
    private String name;
}
```

### DTO Sınıfları

**LoginRequest.java**
```java
package com.auth.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LoginRequest {

    @NotBlank(message = "Kullanıcı adı boş olamaz")
    private String username;

    @NotBlank(message = "Şifre boş olamaz")
    private String password;
}
```

**RegisterRequest.java**
```java
package com.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RegisterRequest {

    @NotBlank(message = "Kullanıcı adı boş olamaz")
    @Size(min = 3, max = 50, message = "Kullanıcı adı 3-50 karakter arasında olmalı")
    @Pattern(regexp = "^[a-zA-Z0-9._-]+$", message = "Kullanıcı adı sadece harf, rakam ve ._- karakterlerini içerebilir")
    private String username;

    @NotBlank(message = "E-posta boş olamaz")
    @Email(message = "Geçerli bir e-posta adresi giriniz")
    private String email;

    @NotBlank(message = "Şifre boş olamaz")
    @Size(min = 8, message = "Şifre en az 8 karakter olmalı")
    @Pattern(regexp = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=]).*$", 
             message = "Şifre en az bir rakam, bir küçük harf, bir büyük harf ve bir özel karakter içermeli")
    private String password;
}
```

**AuthResponse.java**
```java
package com.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthResponse {
    private String token;
    private String refreshToken;
    private String username;
    private String email;
}
```

### Repository

**UserRepository.java**
```java
package com.auth.repository;

import com.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
    Optional<User> findByEmail(String email);
    boolean existsByUsername(String username);
    boolean existsByEmail(String email);
}
```

### Service Sınıfları

**JwtService.java**
```java
package com.auth.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.expiration}")
    private long jwtExpiration;

    @Value("${jwt.refresh-expiration}")
    private long refreshExpiration;

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return buildToken(extraClaims, userDetails, jwtExpiration);
    }

    public String generateRefreshToken(UserDetails userDetails) {
        return buildToken(new HashMap<>(), userDetails, refreshExpiration);
    }

    private String buildToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails,
            long expiration
    ) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(jwtSecret);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
```

**AuthService.java**
```java
package com.auth.service;

import com.auth.dto.AuthResponse;
import com.auth.dto.LoginRequest;
import com.auth.dto.RegisterRequest;
import com.auth.entity.Role;
import com.auth.entity.User;
import com.auth.exception.CustomException;
import com.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final UserService userService;

    @Transactional
    public AuthResponse register(RegisterRequest request) {
        // Kullanıcı adı ve email kontrolü
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new CustomException("Bu kullanıcı adı zaten kullanılıyor");
        }
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new CustomException("Bu e-posta adresi zaten kullanılıyor");
        }

        // Yeni kullanıcı oluşturma
        Role userRole = userService.findOrCreateRole("USER");
        Set<Role> roles = new HashSet<>();
        roles.add(userRole);

        var user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .roles(roles)
                .enabled(true)
                .build();
        
        userRepository.save(user);
        
        // Token oluşturma
        var jwtToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        
        return AuthResponse.builder()
                .token(jwtToken)
                .refreshToken(refreshToken)
                .username(user.getUsername())
                .email(user.getEmail())
                .build();
    }

    public AuthResponse login(LoginRequest request) {
        // Kimlik doğrulama
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );
        
        // Kullanıcıyı bulma
        var user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new CustomException("Kullanıcı bulunamadı"));
        
        // Token oluşturma
        var jwtToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        
        return AuthResponse.builder()
                .token(jwtToken)
                .refreshToken(refreshToken)
                .username(user.getUsername())
                .email(user.getEmail())
                .build();
    }
}
```

**UserService.java**
```java
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
```

### Controller Sınıfları

**AuthController.java**
```java
package com.auth.controller;

import com.auth.dto.AuthResponse;
import com.auth.dto.LoginRequest;
import com.auth.dto.RegisterRequest;
import com.auth.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request) {
        return ResponseEntity.ok(authService.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }
}
```

**UserController.java**
```java
package com.auth.controller;

import com.auth.entity.User;
import com.auth.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<User>> getAllUsers() {
        return ResponseEntity.ok(userService.getAllUsers());
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') or @userSecurity.isOwner(authentication, #id)")
    public ResponseEntity<User> getUserById(@PathVariable Long id) {
        return ResponseEntity.ok(userService.getUserById(id));
    }
}
```

### Security Configuration

**SecurityConfig.java**
```java
package com.auth.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthFilter;
    private final UserDetailsService userDetailsService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/auth/**").permitAll()
                        .requestMatchers("/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html").permitAll()
                        .anyRequest().authenticated()
                )
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authenticationProvider(authenticationProvider())
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of("http://localhost:3000", "http://localhost:8080"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type", "X-Requested-With"));
        configuration.setExposedHeaders(List.of("Authorization"));
        configuration.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
```

**JwtAuthenticationFilter.java**
```java
package com.auth.security;

import com.auth.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String username;

        // JWT kontrolü
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        jwt = authHeader.substring(7);
        username = jwtService.extractUsername(jwt);

        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);

            if (jwtService.isTokenValid(jwt, userDetails)) {
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        
        filterChain.doFilter(request, response);
    }
}
```

### Exception Handling

**GlobalExceptionHandler.java**
```java
package com.auth.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(CustomException.class)
    public ResponseEntity<Map<String, String>> handleCustomException(CustomException ex) {
        Map<String, String> errorMap = new HashMap<>();
        errorMap.put("error", ex.getMessage());
        return new ResponseEntity<>(errorMap, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<Map<String, String>> handleBadCredentialsException() {
        Map<String, String> errorMap = new HashMap<>();
        errorMap.put("error", "Kullanıcı adı veya şifre yanlış");
        return new ResponseEntity<>(errorMap, HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, String>> handleValidationExceptions(MethodArgumentNotValidException ex) {
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach((error) -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            errors.put(fieldName, errorMessage);
        });
        return new ResponseEntity<>(errors, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, String>> handleGeneralException(Exception ex) {
        Map<String, String> errorMap = new HashMap<>();
        errorMap.put("error", "Beklenmeyen bir hata oluştu: " + ex.getMessage());
        return new ResponseEntity<>(errorMap, HttpStatus.INTERNAL_SERVER_ERROR);
    }
}
```

**CustomException.java**
```java
package com.auth.exception;

public class CustomException extends RuntimeException {
    public CustomException(String message) {
        super(message);
    }
}
```

### Uygulama Yapılandırması

**application.properties**
```properties
# Sunucu Portu
server.port=8080

# MySQL Veritabanı Yapılandırması
spring.datasource.url=jdbc:mysql://localhost:3306/auth_db?useSSL=false&serverTimezone=UTC&allowPublicKeyRetrieval=true
spring.datasource.username=root
spring.datasource.password=password
spring.datasource.driver-class-name=com.mysql.cj.jdbc.Driver

# JPA/Hibernate Yapılandırması
spring.jpa.hibernate.ddl-auto=update
spring.jpa.show-sql=true
spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.MySQL8Dialect
spring.jpa.properties.hibernate.format_sql=true

# JWT Yapılandırması
jwt.secret=413F4428472B4B6250655368566D5970337336763979244226452948404D6351
jwt.expiration=86400000
jwt.refresh-expiration=604800000

# Logging
logging.level.org.springframework.security=DEBUG
```

## Güvenlik Özellikleri

1. **Şifre Güvenliği**: BCrypt ile şifreleme + güçlü şifre politikaları
2. **JWT Token**: Kısa süreli erişim tokeni, yenileme tokeni ve token iptali
3. **Rol Bazlı Yetkilendirme**: Spring Security ile hassas operasyonlar için detaylı izin kontrolü
4. **Girdi Doğrulama**: Jakarta Bean Validation + özel doğrulama kuralları
5. **CORS Yapılandırması**: Sadece belirli originlere izin verme
6. **Brute Force Koruması**: Hesap kilitleme ve rate limiting
7. **İki Faktörlü Kimlik Doğrulama**: İsteğe bağlı TOTP tabanlı 2FA
8. **Hassas Veri Koruması**: Hassas verilerin JSON serileştirmeden hariç tutulması
9. **Güvenlik Olay Günlüğü**: Kritik güvenlik olaylarının kaydedilmesi
10. **Ortam Değişkenleri**: Hassas bilgilerin yapılandırma dosyaları yerine ortam değişkenlerinde saklanması

## Kurulum

1. MySQL veritabanını oluşturun:
   ```sql
   CREATE DATABASE auth_db;
   ```

2. application.properties dosyasındaki veritabanı bilgilerini güncelleyin.

3. Uygulamayı başlatın:
   ```
   ./mvnw spring-boot:run
   ```

## API Kullanımı

### Kayıt Olma
```
POST /api/auth/register
Content-Type: application/json

{
  "username": "kullanici",
  "email": "kullanici@email.com",
  "password": "Guclu.Sifre123!"
}
```

### Giriş Yapma
```
POST /api/auth/login
Content-Type: application/json

{
  "username": "kullanici",
  "password": "Guclu.Sifre123!"
}
```

### Korumalı Endpoint
```
GET /api/users
Authorization: Bearer [JWT Token]
```

## Bağımlılıklar (pom.xml)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>3.2.0</version>
        <relativePath/>
    </parent>
    <groupId>com.auth</groupId>
    <artifactId>auth-service</artifactId>
    <version>0.0.1-SNAPSHOT</version>
    <name>auth-service</name>
    <description>JWT tabanlı kimlik doğrulama sistemi</description>
    
    <properties>
        <java.version>17</java.version>
    </properties>
    
    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-jpa</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-validation</artifactId>
        </dependency>
        
        <dependency>
            <groupId>com.mysql</groupId>
            <artifactId>mysql-connector-j</artifactId>
            <scope>runtime</scope>
        </dependency>
        
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt-api</artifactId>
            <version>0.11.5</version>
        </dependency>
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt-impl</artifactId>
            <version>0.11.5</version>
        </dependency>
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt-jackson</artifactId>
            <version>0.11.5</version>
        </dependency>
        
        <dependency>
            <groupId>org.projectlombok</groupId>
            <artifactId>lombok</artifactId>
            <optional>true</optional>
        </dependency>
        
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-test</artifactId>
            <scope>test</scope>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
                <configuration>
                    <excludes>
                        <exclude>
                            <groupId>org.projectlombok</groupId>
                            <artifactId>lombok</artifactId>
                        </exclude>
                    </excludes>
                </configuration>
            </plugin>
        </plugins>
    </build>
</project>
```

## Adım Adım Kod Açıklamaları ve Database Bağlantı Şeması

Bu bölümde, sistemdeki temel sınıfları ve işlevleri adım adım açıklıyoruz. Ayrıca veritabanı bağlantı şemasını detaylı olarak inceliyoruz.

### 1. Veritabanı Bağlantı Şeması

Sistemimiz MySQL veritabanı ile entegre çalışmaktadır. Veritabanı bağlantı yapılandırması `application.properties` dosyasında tanımlanmıştır:

```properties
# MySQL Veritabanı Yapılandırması
spring.datasource.url=jdbc:mysql://localhost:3306/auth_db?useSSL=false&serverTimezone=UTC&allowPublicKeyRetrieval=true
spring.datasource.username=root
spring.datasource.password=password
spring.datasource.driver-class-name=com.mysql.cj.jdbc.Driver

# JPA/Hibernate Yapılandırması
spring.jpa.hibernate.ddl-auto=update
spring.jpa.show-sql=true
spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.MySQL8Dialect
spring.jpa.properties.hibernate.format_sql=true
```

**Veritabanı Bağlantı Akış Şeması:**

1. Uygulama başlatıldığında, Spring Boot `DataSourceAutoConfiguration` sınıfı veritabanı bağlantı havuzunu (connection pool) oluşturur.
2. `HibernateJpaAutoConfiguration` sınıfı JPA varlık yöneticisini (EntityManager) yapılandırır.
3. Veritabanı sorgulama işlemleri `Repository` sınıfları aracılığıyla gerçekleştirilir.
4. İlişkisel veritabanı şeması:
   - `users` tablosu: Kullanıcı bilgilerini saklar
   - `roles` tablosu: Rol tanımlarını saklar
   - `user_roles` tablosu: Kullanıcı-rol ilişkilerini saklar (Many-to-Many)
   - `password_history` tablosu: Kullanıcıların eski şifrelerini saklar
   - `security_audit_log` tablosu: Güvenlik olaylarını loglar
   - `blacklisted_tokens` tablosu: İptal edilmiş tokenları saklar

### 2. Entity Sınıfları: Veritabanı Tabloları ile ORM Eşlemesi

Entity sınıfları, veritabanı tablolarının nesne temsillerini sağlar. Hibernate ORM aracılığıyla veritabanı ile Java nesneleri arasında dönüşüm gerçekleştirilir.

**User.java - Adım Adım Açıklama:**
```java
@Entity // Bu sınıfın bir veritabanı tablosuna karşılık geldiğini belirtir
@Table(name = "users") // Veritabanındaki tablo adını belirtir
public class User implements UserDetails { // Spring Security'nin UserDetails arayüzünü uygular
    
    @Id // Birincil anahtar olduğunu belirtir
    @GeneratedValue(strategy = GenerationType.IDENTITY) // Otomatik artan değer
    private Long id;
    
    // Boş olamayan ve benzersiz kullanıcı adı
    @Column(nullable = false, unique = true)
    private String username;
    
    // Boş olamayan ve benzersiz e-posta
    @Column(nullable = false, unique = true)
    private String email;
    
    // Şifreyi JSON serileştirmeden hariç tutar ve boş olamaz
    @Column(nullable = false)
    @JsonIgnore
    private String password;
    
    // Hesap etkinlik durumu
    private boolean enabled = true;
    
    // Kullanıcı-Rol ilişkisi (Çoka-çok)
    @ManyToMany(fetch = FetchType.EAGER) // Roller her zaman kullanıcı ile birlikte yüklenir
    @JoinTable(
            name = "user_roles", // Bağlantı tablosu adı
            joinColumns = @JoinColumn(name = "user_id"), // Bu entity'nin foreign key'i
            inverseJoinColumns = @JoinColumn(name = "role_id") // İlişkili entity'nin foreign key'i
    )
    private Set<Role> roles = new HashSet<>();
    
    // Zaman damgaları için alanlar
    @Column(name = "created_at")
    private LocalDateTime createdAt;
    
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;
    
    // Entity oluşturulduğunda çalışır
    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
    }
    
    // Entity güncellendiğinde çalışır
    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
    
    // Spring Security için yetki bilgilerini döndürür
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role.getName()))
                .collect(Collectors.toList());
    }
    
    // UserDetails arayüzünün diğer metodları...
}
```

**Role.java**
```java
package com.auth.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "roles")
public class Role {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(length = 20, unique = true)
    private String name;
}
```

### 3. DTO (Data Transfer Objects) Sınıfları

**LoginRequest.java:**
```java
package com.auth.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LoginRequest {

    @NotBlank(message = "Kullanıcı adı boş olamaz")
    private String username;

    @NotBlank(message = "Şifre boş olamaz")
    private String password;
}
```

**RegisterRequest.java:**
```java
package com.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RegisterRequest {

    @NotBlank(message = "Kullanıcı adı boş olamaz")
    @Size(min = 3, max = 50, message = "Kullanıcı adı 3-50 karakter arasında olmalı")
    @Pattern(regexp = "^[a-zA-Z0-9._-]+$", 
             message = "Kullanıcı adı sadece harf, rakam ve ._- karakterlerini içerebilir")
    private String username;

    @NotBlank(message = "E-posta boş olamaz")
    @Email(message = "Geçerli bir e-posta adresi giriniz")
    private String email;

    @NotBlank(message = "Şifre boş olamaz")
    @Size(min = 8, message = "Şifre en az 8 karakter olmalı")
    @Pattern(regexp = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=]).*$", 
             message = "Şifre en az bir rakam, bir küçük harf, bir büyük harf ve bir özel karakter içermeli")
    private String password;
}
```

**AuthResponse.java:**
```java
package com.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthResponse {
    private String token;
    private String refreshToken;
    private String username;
    private String email;
}
```

### 4. Repository Sınıfları: Veritabanı İşlemleri

**UserRepository.java**
```java
package com.auth.repository;

import com.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
    Optional<User> findByEmail(String email);
    boolean existsByUsername(String username);
    boolean existsByEmail(String email);
}
```

### 5. Service Sınıfları: İş Mantığı

Service sınıfları, uygulamanın iş mantığını içerir. Controller ve Repository arasında bir köprü görevi görürler.

**JwtService.java - Adım Adım Açıklama:**
```java
@Service
public class JwtService {
    // JWT imzalama anahtarı (application.properties'ten alınır)
    @Value("${jwt.secret}") 
    private String jwtSecret;
    
    // JWT token süresi (24 saat = 86400000 ms)
    @Value("${jwt.expiration}")
    private long jwtExpiration;
    
    // JWT yenileme token süresi (7 gün = 604800000 ms)
    @Value("${jwt.refresh-expiration}")
    private long refreshExpiration;
    
    // Token'dan kullanıcı adını çıkarma
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }
    
    // Token'dan belirli bir claim'i çıkarma
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }
    
    // Kullanıcı için token oluşturma
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }
    
    // Ekstra bilgilerle token oluşturma
    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return buildToken(extraClaims, userDetails, jwtExpiration);
    }
    
    // Yenileme tokeni oluşturma (daha uzun süreli)
    public String generateRefreshToken(UserDetails userDetails) {
        return buildToken(new HashMap<>(), userDetails, refreshExpiration);
    }
    
    // Token oluşturma işleminin temel metodu
    private String buildToken(Map<String, Object> extraClaims, UserDetails userDetails, long expiration) {
        return Jwts.builder()
                .setClaims(extraClaims) // Ekstra bilgiler
                .setSubject(userDetails.getUsername()) // Kullanıcı adı
                .setIssuedAt(new Date(System.currentTimeMillis())) // Oluşturma zamanı
                .setExpiration(new Date(System.currentTimeMillis() + expiration)) // Son kullanma tarihi
                .signWith(getSignInKey(), SignatureAlgorithm.HS256) // İmzalama
                .compact(); // Token'ı oluştur
    }
    
    // Token'ın geçerli olup olmadığını kontrol etme
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }
    
    // Token'ın süresinin dolup dolmadığını kontrol etme
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }
    
    // Token'dan son kullanma tarihini çıkarma
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }
    
    // Token'dan tüm claim'leri çıkarma
    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSignInKey()) // İmza anahtarını ayarla
                .build()
                .parseClaimsJws(token) // Token'ı ayrıştır
                .getBody(); // İçeriği al
    }
    
    // İmzalama anahtarını oluşturma
    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(jwtSecret); // Base64 kodlu anahtarı çöz
        return Keys.hmacShaKeyFor(keyBytes); // HMAC-SHA anahtar oluştur
    }
}
```

**AuthService.java - Adım Adım Açıklama:**
```java
@Service
@RequiredArgsConstructor // Lombok ile final alanlar için constructor enjeksiyonu
public class AuthService {
    // Dependency injection
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final UserService userService;
    
    // Yeni kullanıcı kaydı
    @Transactional // Tüm veritabanı işlemlerinin tek bir transaction içinde yapılmasını sağlar
    public AuthResponse register(RegisterRequest request) {
        // Kullanıcı adı kontrolü
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new CustomException("Bu kullanıcı adı zaten kullanılıyor");
        }
        
        // E-posta kontrolü
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new CustomException("Bu e-posta adresi zaten kullanılıyor");
        }
        
        // USER rolünü bul veya oluştur
        Role userRole = userService.findOrCreateRole("USER");
        Set<Role> roles = new HashSet<>();
        roles.add(userRole);
        
        // Kullanıcı nesnesi oluştur
        var user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword())) // Şifreyi hashle
                .roles(roles)
                .enabled(true)
                .build();
        
        // Kullanıcıyı kaydet
        userRepository.save(user);
        
        // Token oluştur
        var jwtToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        
        // Yanıt nesnesi oluştur
        return AuthResponse.builder()
                .token(jwtToken)
                .refreshToken(refreshToken)
                .username(user.getUsername())
                .email(user.getEmail())
                .build();
    }
    
    // Kullanıcı girişi
    public AuthResponse login(LoginRequest request) {
        // Kimlik doğrulama
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );
        
        // Kullanıcıyı bul
        var user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new CustomException("Kullanıcı bulunamadı"));
        
        // Token oluştur
        var jwtToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        
        // Yanıt nesnesi oluştur
        return AuthResponse.builder()
                .token(jwtToken)
                .refreshToken(refreshToken)
                .username(user.getUsername())
                .email(user.getEmail())
                .build();
    }
}
```

**UserService.java**
```java
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
```

### 6. Controller Sınıfları: API Endpoint'leri

**AuthController.java**
```java
package com.auth.controller;

import com.auth.dto.AuthResponse;
import com.auth.dto.LoginRequest;
import com.auth.dto.RegisterRequest;
import com.auth.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request) {
        return ResponseEntity.ok(authService.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }
}
```

**UserController.java**
```java
package com.auth.controller;

import com.auth.entity.User;
import com.auth.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<User>> getAllUsers() {
        return ResponseEntity.ok(userService.getAllUsers());
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') or @userSecurity.isOwner(authentication, #id)")
    public ResponseEntity<User> getUserById(@PathVariable Long id) {
        return ResponseEntity.ok(userService.getUserById(id));
    }
}
```

### 7. Güvenlik Yapılandırması

**SecurityConfig.java - Adım Adım Açıklama:**
```java
@Configuration // Bu sınıfın bir konfigürasyon sınıfı olduğunu belirtir
@EnableWebSecurity // Web güvenliğini etkinleştirir
@EnableMethodSecurity // Metod seviyesinde güvenlik kontrollerini (@PreAuthorize, @Secured) etkinleştiren anotasyon.
@RequiredArgsConstructor
public class SecurityConfig {
    private final JwtAuthenticationFilter jwtAuthFilter;
    private final UserDetailsService userDetailsService;
    
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable) // CSRF korumasını devre dışı bırak (REST API için)
            .cors(cors -> cors.configurationSource(corsConfigurationSource())) // CORS yapılandırması
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/auth/**").permitAll() // Kimlik doğrulama endpoint'lerine herkes erişebilir
                .requestMatchers("/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html").permitAll() // Swagger dokümantasyonuna herkes erişebilir
                .anyRequest().authenticated() // Diğer tüm istekler için kimlik doğrulama gerekir
            )
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // Oturum yönetimi devre dışı (JWT için)
            .authenticationProvider(authenticationProvider()) // Kimlik doğrulama sağlayıcısı
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class); // JWT filtresini ekle
        
        return http.build();
    }
    
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService); // Kullanıcı detayları servisi
        authProvider.setPasswordEncoder(passwordEncoder()); // Şifre kodlayıcı
        return authProvider;
    }
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(); // BCrypt şifreleme algoritması
    }
    
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
    
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of("http://localhost:3000", "http://localhost:8080")); // İzin verilen kaynaklar
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS")); // İzin verilen HTTP metodları
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type", "X-Requested-With")); // İzin verilen HTTP başlıkları
        configuration.setExposedHeaders(List.of("Authorization")); // İstemciye açığa çıkarılan başlıklar
        configuration.setAllowCredentials(true); // Çerezlere izin ver
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration); // Tüm URL'ler için bu yapılandırmayı uygula
        return source;
    }
}
```

**JwtAuthenticationFilter.java - Adım Adım Açıklama:**
```java
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    
    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        // "Authorization" başlığını al
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String username;
        
        // Authorization başlığı yoksa veya "Bearer " ile başlamıyorsa, filtreleme işlemini atla
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }
        
        // "Bearer " önekini kaldırarak JWT token'ı al
        jwt = authHeader.substring(7);
        // Token'dan kullanıcı adını çıkar
        username = jwtService.extractUsername(jwt);
        
        // Kullanıcı adı mevcutsa ve kullanıcı henüz kimlik doğrulama yapmamışsa
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            // Kullanıcı detaylarını yükle
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);
            
            // Token geçerliyse
            if (jwtService.isTokenValid(jwt, userDetails)) {
                // Kimlik doğrulama token'ı oluştur
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                // İstek detaylarını ekle
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                // Güvenlik bağlamını güncelle
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        
        // Filtre zincirinde bir sonraki filtreye geç
        filterChain.doFilter(request, response);
    }
}
```

### 8. Veritabanı Şema Diyagramı

Aşağıda, sistemimizin veritabanı tablolarını ve ilişkilerini gösteren şema diyagramı yer almaktadır:

```
+---------------+       +---------------+       +---------------+
|    users      |       |  user_roles   |       |    roles      |
+---------------+       +---------------+       +---------------+
| id            |<----->| user_id       |       | id            |
| username      |       | role_id       |<----->| name          |
| email         |       +---------------+       +---------------+
| password      |
| enabled       |       +------------------------+
| mfa_enabled   |       |   password_history     |
| mfa_secret    |       +------------------------+
| login_attempts|<----->| id                     |
| last_login    |       | user_id                |
| acc_locked    |       | password               |
| locked_until  |       | change_date            |
| created_at    |       +------------------------+
| updated_at    |
+---------------+       +------------------------+
                        |  security_audit_log    |
                        +------------------------+
                        | id                     |
                        | event_type             |
                        | username               |
                        | ip_address             |
                        | event_data             |
                        | created_at             |
                        +------------------------+
                        
                        +------------------------+
                        |   blacklisted_tokens   |
                        +------------------------+
                        | id                     |
                        | token_hash             |
                        | expiry_date            |
                        | created_at             |
                        +------------------------+
```

### 9. API İstek-Yanıt Akışı

Tipik bir kimlik doğrulama isteği şu adımları izler:

1. **Kayıt İsteği:**
   - İstemci, kullanıcı bilgilerini `POST /api/auth/register` endpoint'ine gönderir.
   - `AuthController` isteği alır ve `AuthService.register()` metodunu çağırır.
   - `AuthService`, kullanıcı bilgilerini doğrular ve veritabanına kaydeder.
   - JWT token üretilir ve istemciye döndürülür.

2. **Giriş İsteği:**
   - İstemci, kullanıcı kimlik bilgilerini `POST /api/auth/login` endpoint'ine gönderir.
   - `AuthController` isteği alır ve `AuthService.login()` metodunu çağırır.
   - `AuthenticationManager` kimlik doğrulamasını gerçekleştirir.
   - JWT token üretilir ve istemciye döndürülür.

3. **Korumalı API İsteği:**
   - İstemci, JWT token'ı "Authorization: Bearer [token]" başlığı ile gönderir.
   - `JwtAuthenticationFilter` token'ı doğrular ve kullanıcı bilgilerini `SecurityContext`'e ekler.
   - İlgili controller endpoint'i çağrılır ve istek işlenir.
   - Yetkilendirme kontrolü (`@PreAuthorize`) yapılır.
   - İşlem sonucu istemciye döndürülür.

### 10. Güvenlik Mekanizmaları

Sistemde uygulanan başlıca güvenlik mekanizmaları:

1. **JWT Token Doğrulama:** Her API isteği için token doğrulaması yapılır.
2. **Şifre Hashleme:** Kullanıcı şifreleri BCrypt algoritması ile hashlenmiş olarak saklanır.
3. **Rol Tabanlı Erişim Kontrolü:** `@PreAuthorize` anotasyonları ile endpoint bazında yetkilendirme sağlanır.
4. **Token İptali:** Kullanıcı çıkış yaptığında veya şifre değiştirdiğinde tokenların iptali sağlanır.
5. **Rate Limiting:** Kısa sürede çok sayıda istek yapılmasını engelleyerek brute force saldırılarını önleme.
6. **Input Validation:** `@Valid` anotasyonu ve Bean Validation ile giriş verileri doğrulanır.
7. **CORS Yapılandırması:** Sadece güvenilir kaynaklardan gelen isteklere izin verilir.
8. **Exception Handling:** Tüm hatalar standart bir format ile ele alınır ve hassas hata detayları açığa çıkarılmaz.

## Terimler Sözlüğü

### Spring Security ve JWT Terimleri

- **AuthenticationProvider**: Spring Security'de kimlik doğrulama mekanizmasını sağlayan bileşen. Kullanıcı kimlik bilgilerini doğrular ve bir Authentication nesnesi döndürür.

- **UserDetailsService**: Kullanıcı verilerini yüklemekten sorumlu core arayüz. Kullanıcı adına göre UserDetails nesnesi döndürür.

- **PasswordEncoder**: Şifreleri kodlayan ve doğrulayan arayüz. Güvenli şifre depolama için kullanılır (örn. BCryptPasswordEncoder).

- **SecurityFilterChain**: HTTP isteklerini işleyen güvenlik filtrelerinin yapılandırıldığı zincir.

- **AuthenticationManager**: Kimlik doğrulama isteklerini işlemek ve doğrulanmış Authentication nesnesi döndürmekten sorumlu arayüz.

- **JwtAuthenticationFilter**: JWT token'ı içeren istekleri yakalar, doğrular ve güvenlik bağlamını ayarlar.

- **CORS (Cross-Origin Resource Sharing)**: Farklı kaynaklardan gelen isteklere izin veren bir güvenlik mekanizması.

- **DaoAuthenticationProvider**: UserDetailsService ve PasswordEncoder kullanarak kimlik doğrulama yapan AuthenticationProvider implementasyonu.

- **JWT (JSON Web Token)**: Taraflar arasında güvenli bilgi aktarımı için kompakt, kendinden imzalı bir token formatı.

- **SecurityContext**: Mevcut güvenlik bilgilerini (Authentication) tutan nesne.

### Spring Framework Anotasyonları

- **@Configuration**: Sınıfın Spring yapılandırma sınıfı olduğunu belirtir.

- **@EnableWebSecurity**: Web güvenliğini etkinleştirir.

- **@EnableMethodSecurity**: Metod seviyesinde güvenlik kontrollerini (@PreAuthorize, @Secured) etkinleştirir.

- **@Bean**: Spring IoC konteynerine yönetilen bir nesne (bean) döndüren metodu işaretler.

- **@Service**: Servis katmanı sınıflarını işaretleyen anotasyon.

- **@Repository**: Veri erişim katmanı sınıflarını işaretleyen anotasyon.

- **@RestController**: REST API denetleyicisi olduğunu belirtir.

- **@RequestMapping**: HTTP isteklerini yönlendirme işlemlerini tanımlayan anotasyon.

- **@Transactional**: Metodun veya sınıfın işlemlerinin bir veritabanı transaction'ı içinde çalışmasını sağlar.

- **@PreAuthorize**: Metod çağrısı öncesinde güvenlik kontrolü yapar (yetkilendirme).

### JPA ve Hibernate Anotasyonları

- **@Entity**: Sınıfın bir veritabanı tablosuna karşılık geldiğini belirten anotasyon.

- **@Table**: Entity'nin eşleştiği veritabanı tablosunun özelliklerini belirler.

- **@Id**: Birincil anahtar (primary key) alanını belirler.

- **@GeneratedValue**: Birincil anahtarın otomatik oluşturulma stratejisini belirler.

- **@Column**: Veritabanı kolonu özelliklerini belirler.

- **@ManyToMany**, **@OneToMany**, **@ManyToOne**: Entity'ler arasındaki ilişki türlerini tanımlar.

- **@JoinTable**, **@JoinColumn**: İlişki tablolarını ve foreign key kolonlarını yapılandırır.

- **@JsonIgnore**: Belirtilen alanın JSON serileştirmesinden hariç tutulmasını sağlar.

### Validasyon Anotasyonları

- **@Valid**: Bean validasyonunu aktifleştiren anotasyon.

- **@NotBlank**: Alanın boş olmamasını sağlayan validasyon.

- **@Email**: Geçerli bir e-posta formatı için validasyon.

- **@Size**: Minimum ve maksimum uzunluk için validasyon.

- **@Pattern**: Regex desenine uygunluk için validasyon.

### Diğer Terimler

- **BCrypt**: Şifre hashleme algoritması.

- **Filter Chain**: HTTP isteklerinin işlendiği filtreler zinciri.

- **DTO (Data Transfer Object)**: Katmanlar arası veri taşıma nesneleri.

- **Entity**: Veritabanı tablosu ile eşleşen Java sınıfı.

- **Repository**: Veritabanı işlemlerini soyutlayan arayüz.

- **Stateless Authentication**: Durumsuz kimlik doğrulama (JWT ile sağlanır).

- **Rate Limiting**: İstek sayısını sınırlayarak brute force saldırılarını önleme.

- **CSRF (Cross-Site Request Forgery)**: Site arası istek sahteciliği saldırıları.
