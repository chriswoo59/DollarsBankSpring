package com.dollarsbank.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration{

	@Autowired
	UserDetailsService userDetailsService;

//	@Autowired
//	JwtRequestFilter jwtRequestFilter;
	

	// Authentication
	@Bean
	protected UserDetailsService userDetailsService() {
		return userDetailsService;
	}

	@Bean
	protected PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	protected DaoAuthenticationProvider authenticationProvider() {

		DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();

		authProvider.setUserDetailsService(userDetailsService);
		authProvider.setPasswordEncoder(passwordEncoder());

		return authProvider;
	}

	// can autowire and access the authentication manager (manages authentication (login) of our project)
	@Bean
	protected AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
		return authConfig.getAuthenticationManager();
	}

	@Bean
	protected SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http.httpBasic()
			.and().cors()
			.and().csrf().disable()
			.authorizeHttpRequests()
			.requestMatchers(HttpMethod.POST, "/api/users/register").permitAll()
			.requestMatchers(HttpMethod.POST, "/api/users/login").permitAll()
			.requestMatchers(HttpMethod.GET, "/api/users/loggedin").permitAll()
			.requestMatchers(HttpMethod.PUT, "/api/users/{username}").hasRole("ADMIN")
			.requestMatchers(HttpMethod.DELETE, "/api/users/{username}").hasRole("ADMIN")
			.anyRequest().authenticated();

		return http.build();
	}

	@Bean
    CorsConfigurationSource corsConfigurationSource() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", new CorsConfiguration().applyPermitDefaultValues());
        return source;
    }
}
