//package edu.iu.p466.prime_service.security;
//
//import com.nimbusds.jose.JOSEException;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.http.HttpMethod;
//import org.springframework.security.authentication.AuthenticationManager;
//import org.springframework.security.authentication.ProviderManager;
//import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
//import org.springframework.security.config.Customizer;
//import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.config.http.SessionCreationPolicy;
//import org.springframework.security.core.context.SecurityContext;
//import com.nimbusds.jose.jwk.RSAKey;
//import com.nimbusds.jose.jwk.JWKSet;
//import com.nimbusds.jose.jwk.source.JWKSource;
//import org.springframework.security.core.userdetails.UserDetailsService;
//import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//import org.springframework.security.oauth2.jwt.JwtDecoder;
//import org.springframework.security.oauth2.jwt.JwtEncoder;
//import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
//import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
//import org.springframework.security.web.SecurityFilterChain;
//import org.springframework.web.cors.CorsConfiguration;
//
//import java.util.List;
//
//@Configuration
//@EnableWebSecurity
//@EnableMethodSecurity
//public class SecurityConfig {
//    private RSAKey rsaKey;
//
//    public SecurityConfig() {
//        this.rsaKey = Jwks.generateRsa();
//    }
//
//
//    @Bean
//    public JWKSource<com.nimbusds.jose.proc.SecurityContext> jwkSource() {
//        JWKSet jwkSet = new JWKSet(rsaKey);
//        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
//    }
//
//    @Bean
//    JwtEncoder jwtEncoder(JWKSource<com.nimbusds.jose.proc.SecurityContext> jwks)  {
//        return new NimbusJwtEncoder(jwks);
//    }
//
//    @Bean
//    JwtDecoder jwtDecoder() throws JOSEException {
//        return NimbusJwtDecoder.withPublicKey(rsaKey.toRSAPublicKey()).build();
//    }
//
////    @Bean
////    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
////        return http
////                .cors(Customizer.withDefaults())
////                .csrf(x -> x.disable())
////                .authorizeHttpRequests( auth -> auth
////                        .requestMatchers(
////                                HttpMethod.POST,"/register", "/login").permitAll()
////                        .anyRequest().authenticated()
////                )
////                .sessionManagement(session ->
////                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
////                .oauth2ResourceServer((oauth2) -> oauth2.jwt(Customizer.withDefaults()))
////                .build();
////    }
//
//    @Override
//    public void addCorsMappings(CorsRegistry registry) {
//        // Allow CORS for frontend
//        registry.addMapping("/**")
//                .allowedOrigins("http://127.0.0.1:5500")  // Frontend origin
//                .allowedMethods("GET", "POST", "PUT", "DELETE")  // Allowed HTTP methods
//                .allowedHeaders("Authorization", "Content-Type")  // Allowed headers
//                .allowCredentials(true);  // Allow credentials (cookies, headers)
//    }
//
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http
//                .cors(cors -> cors.configurationSource(request -> {
//                    CorsConfiguration config = new CorsConfiguration();
//                    config.setAllowedOrigins(List.of("http://127.0.0.1:5500", "http://localhost:63342")); // Add frontend origins
//                    config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE"));
//                    config.setAllowedHeaders(List.of("Authorization", "Content-Type"));
//                    config.setAllowCredentials(true);
//                    return config;
//                }))
//                .csrf(csrf -> csrf.disable())  // Disable CSRF for APIs
//                .authorizeHttpRequests(auth -> auth
//                        .requestMatchers(HttpMethod.POST, "/register", "/login").permitAll()
//                        .anyRequest().authenticated()
//                )
//                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
//                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
//
//        return http.build();
//
//    @Bean
//    public AuthenticationManager authManager(UserDetailsService userDetailsService) {
//        var authProvider = new DaoAuthenticationProvider();
//        authProvider.setUserDetailsService(userDetailsService);
//        authProvider.setPasswordEncoder(new BCryptPasswordEncoder());
//        return new ProviderManager(authProvider);
//    }
//}

package edu.iu.p466.prime_service.security;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.List;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig implements WebMvcConfigurer {

    private RSAKey rsaKey;

    public SecurityConfig() {
        this.rsaKey = Jwks.generateRsa();
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    @Bean
    JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwks) {
        return new NimbusJwtEncoder(jwks);
    }

    @Bean
    JwtDecoder jwtDecoder() throws JOSEException {
        return NimbusJwtDecoder.withPublicKey(rsaKey.toRSAPublicKey()).build();
    }

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        // Allow CORS for frontend
        registry.addMapping("/**")
                .allowedOrigins("http://127.0.0.1:5500")  // Frontend origin
                .allowedMethods("GET", "POST", "PUT", "DELETE")  // Allowed HTTP methods
                .allowedHeaders("Authorization", "Content-Type")  // Allowed headers
                .allowCredentials(true);  // Allow credentials (cookies, headers)
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .cors(cors -> cors.configurationSource(request -> {
                    CorsConfiguration config = new CorsConfiguration();
                    config.setAllowedOrigins(List.of("http://127.0.0.1:5500", "http://localhost:63342")); // Add frontend origins
                    config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE"));
                    config.setAllowedHeaders(List.of("Authorization", "Content-Type"));
                    config.setAllowCredentials(true);
                    return config;
                }))
                .csrf(csrf -> csrf.disable())  // Disable CSRF for APIs
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.POST, "/register", "/login").permitAll()
                        .anyRequest().authenticated()
                )
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));

        return http.build();
    }


    @Bean
    public AuthenticationManager authManager(UserDetailsService userDetailsService) {
        var authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(new BCryptPasswordEncoder());
        return new ProviderManager(authProvider);
    }
}
