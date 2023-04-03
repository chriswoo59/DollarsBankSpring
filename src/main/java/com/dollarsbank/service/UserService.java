package com.dollarsbank.service;

import java.security.Principal;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.stereotype.Service;

import com.dollarsbank.model.Credentials;
import com.dollarsbank.model.User;
import com.dollarsbank.repository.UserRepository;
//import com.dollarsbank.util.JwtUtil;

import jakarta.persistence.EntityExistsException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

@Service
public class UserService {

	@Autowired
	UserRepository userRepo;
	
	@Autowired
	PasswordEncoder encoder;
	
	@Autowired
	AuthenticationManager authManager;
	
	@Autowired
	UserDetailsService userDetailsService;
	
//	@Autowired
//	JwtUtil jwtUtil;

	public ResponseEntity<?> createUser(User user) {
		if (user != null) {
			if (userRepo.findByUsernameIgnoreCase(user.getUsername()).isPresent()) {
				throw new EntityExistsException("Username already in database");
			}
			// Encode password
			user.setPassword(encoder.encode(user.getPassword()));
			
			userRepo.save(user);
			return new ResponseEntity<>(user, HttpStatus.ACCEPTED);
		}
		else {
			return new ResponseEntity<>("Failed to create user " + user, HttpStatus.NOT_ACCEPTABLE);
		}
	}
	
	public ResponseEntity<?> login(HttpServletRequest req, Credentials credentials) {
		String username = credentials.getUsername();
		String password = credentials.getPassword();
		UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password);
		try {
			Authentication authentication = authManager.authenticate(authToken);
	        System.out.println("Logging in with [" + authentication.getPrincipal() + "]");
	        SecurityContext sc = SecurityContextHolder.getContext();
	        sc.setAuthentication(authentication);
	        HttpSession session = req.getSession(true);
	        session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, sc);
		}
		catch (Exception e) {
			return new ResponseEntity<>("Failed to authenticate", HttpStatus.NOT_FOUND);
		}
		// User is valid
		UserDetails userDetails = userDetailsService.loadUserByUsername(username);
		
		
		return new ResponseEntity<>(userDetails, HttpStatus.CREATED);
	}
	
//	public ResponseEntity<?> authenticate(String username, String password) {
//		try {
//			authManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
//		}
//		catch (Exception e) {
//			return new ResponseEntity<>("Failed to authenticate", HttpStatus.NOT_FOUND);
//		}
//		// User is valid
//		UserDetails userDetails = userDetailsService.loadUserByUsername(username);
//		String jwt = jwtUtil.generateTokens(userDetails);
//		
//		return new ResponseEntity<>(jwt, HttpStatus.CREATED);
//	}
	public ResponseEntity<?> getLoggedInUser() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if ((authentication instanceof AnonymousAuthenticationToken)) {
			return new ResponseEntity<>("No user logged in.", HttpStatus.NOT_FOUND);
		}
		String username = authentication.getName();
		Optional<User> found = userRepo.findByUsernameIgnoreCase(username);
		if (found.isEmpty()) {
			return new ResponseEntity<>("User with specified username not found: " + username, HttpStatus.NOT_FOUND);
		}
		return new ResponseEntity<>(found.get(), HttpStatus.FOUND);
	}

	public ResponseEntity<?> getAllUsers() {
		return new ResponseEntity<>(userRepo.findAll(), HttpStatus.FOUND);
	}

	public ResponseEntity<?> getUserByUsername(String username) {
		Optional<User> found = userRepo.findByUsernameIgnoreCase(username);
		if (found.isPresent()) {
			return new ResponseEntity<>(found.get(), HttpStatus.FOUND);
		}
		else {
			return new ResponseEntity<>("User with specified username not found.", HttpStatus.NOT_FOUND);
		}
	}
	
	public ResponseEntity<?> getHistory() {
		String username = SecurityContextHolder.getContext().getAuthentication().getName();
		Optional<User> found = userRepo.findByUsernameIgnoreCase(username);
		if (found.isPresent()) {
			List<String> history = found.get().getHistory();
			// Reverse list to get last 5 using stream
			Collections.reverse(history);
			return new ResponseEntity<>(history.stream().limit(5).collect(Collectors.toList()), HttpStatus.OK);
			
		}
		else {
			return new ResponseEntity<>("User with specified username not found.", HttpStatus.NOT_FOUND);
		}
	}

	public ResponseEntity<?> updateUser(String username, Map<String, Object> userDetails) throws Exception {
		Optional<User> found = userRepo.findByUsernameIgnoreCase(username);
		if (found.isPresent()) {
			User user = found.get();
			// Manually check for every possible variable in json
			if (userDetails.containsKey("username")) {
				String username_ = (String) userDetails.get("username");
				// Check if username is already in database
				if (userRepo.findByUsernameIgnoreCase(username_).isPresent()) {
					throw new EntityExistsException("User" + username_ + "exists in database");
				}
				user.setUsername(username_);
			}
			if (userDetails.containsKey("password")) {
				String password = (String) userDetails.get("password");
				String encoded = encoder.encode(password);
				user.setPassword(encoded);
			}
			if (userDetails.containsKey("email")) {
				String email = (String) userDetails.get("email");
				if (Pattern.compile("^[A-Za-z0-9+_.-]+@(.+)$").matcher(email).matches()) {
					user.setEmail(email);
				} else {
					throw new Exception("Invalid email");
				}
			}
			if (userDetails.containsKey("total")) {
				Double total = (Double) userDetails.get("total");
				user.setTotal(total);
			}
			if (userDetails.containsKey("role")) {
				// Only ADMINs can change user roles
				if (SecurityContextHolder.getContext().getAuthentication().getAuthorities().stream()
					.anyMatch(r -> r.getAuthority().equals("ROLE_ADMIN"))) {
					User.Role role = User.Role.valueOf((String) userDetails.get("role"));
					user.setRole(role);
				} else {
					throw new IllegalAccessException("Only Admins can change user roles");
				}
			}
			
			userRepo.save(user);
			
			return new ResponseEntity<>(user, HttpStatus.OK);
		}
		else {
			return new ResponseEntity<>("User with specified username not found.", HttpStatus.NOT_FOUND);
		}
	}

	public ResponseEntity<?> deposit(Double amount) {
		String username = SecurityContextHolder.getContext().getAuthentication().getName();
		Optional<User> found = userRepo.findByUsernameIgnoreCase(username);
		if (found.isPresent()) {
			found.get().setTotal(found.get().getTotal() + amount);
			found.get().log("Deposit: " + amount);
			
			userRepo.save(found.get());
			return new ResponseEntity<>(amount + " deposited to user " + username, HttpStatus.ACCEPTED);
		}
		else {
			return new ResponseEntity<>("User with specified username not found.", HttpStatus.NOT_FOUND);
		}
	}

	public ResponseEntity<?> withdraw(Double amount) {
		String username = SecurityContextHolder.getContext().getAuthentication().getName();
		Optional<User> found = userRepo.findByUsernameIgnoreCase(username);
		if (found.isPresent()) {
			Double total = found.get().getTotal();
			if (total - amount >= 0) {
				found.get().setTotal(found.get().getTotal() - amount);
				found.get().log("Withdrawal: " + amount);
				
				userRepo.save(found.get());
				return new ResponseEntity<>(amount + " withdrawn from user " + username, HttpStatus.ACCEPTED);
			}
			else {
				// Not enough funds to withdraw
				return new ResponseEntity<>("Only " + total + " left in this account. Cannot withdraw " + amount + ".", HttpStatus.NOT_ACCEPTABLE);
			}
		}
		else {
			return new ResponseEntity<>("User with specified username not found.", HttpStatus.NOT_FOUND);
		}
	}

	public ResponseEntity<?> send(String receiverUsername, Double amount) {
		String senderUsername = SecurityContextHolder.getContext().getAuthentication().getName();
		Optional<User> found1 = userRepo.findByUsernameIgnoreCase(senderUsername);
		Optional<User> found2 = userRepo.findByUsernameIgnoreCase(receiverUsername);
		if (found1.isEmpty()) {
			return new ResponseEntity<>("No user found with username " + senderUsername, HttpStatus.NOT_FOUND);
		}
		else if (found2.isEmpty()) {
			return new ResponseEntity<>("No user found with username " + receiverUsername, HttpStatus.NOT_FOUND);
		}
		User sender = found1.get();
		User receiver = found2.get();
		
		if (sender.getTotal() < amount) {
			return new ResponseEntity<>("Sender does not have enough funds", HttpStatus.NOT_ACCEPTABLE);
		}
		
		sender.setTotal(sender.getTotal() - amount);
		receiver.setTotal(receiver.getTotal() + amount);
		sender.log("Transaction: Sent $" + amount + " to " + receiverUsername);
		receiver.log("Transaction: Received $" + amount + " from " + senderUsername);
		
		userRepo.save(sender);
		userRepo.save(receiver);
		
		
		
		return new ResponseEntity<>("$" + amount + " successfully sent to " + receiverUsername, HttpStatus.ACCEPTED);
	}
	
	public ResponseEntity<?> deleteUser(String username) {
		Optional<User> found = userRepo.findByUsernameIgnoreCase(username);
		if (found.isPresent()) {
			userRepo.delete(found.get());
			return new ResponseEntity<>(found.get(), HttpStatus.ACCEPTED);
		}
		else {
			return new ResponseEntity<>("User with specified username not found.", HttpStatus.NOT_FOUND);
		}
	}

	

	
}
