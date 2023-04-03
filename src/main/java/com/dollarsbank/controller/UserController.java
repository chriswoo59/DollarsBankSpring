package com.dollarsbank.controller;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.dollarsbank.model.Credentials;
import com.dollarsbank.model.User;
import com.dollarsbank.service.UserService;

import jakarta.servlet.http.HttpServletRequest;

@RestController
@RequestMapping("/api/users")
public class UserController {

	@Autowired
	UserService service;
	
	
	
	@PostMapping("/register")
	public ResponseEntity<?> createUser(@RequestBody User user) {
		return service.createUser(user);
	}
	
	@PostMapping("/login")
	public ResponseEntity<?> login(@RequestBody Credentials credentials, HttpServletRequest req) {
		return service.login(req, credentials);
	}
	
	@GetMapping("/loggedin")
	public ResponseEntity<?> getLoggedIn() {
		return service.getLoggedInUser();
	}
	
	@GetMapping("/all")
	public ResponseEntity<?> getAllUsers() {
		return service.getAllUsers();
	}
	
	@GetMapping("/{username}")
	public ResponseEntity<?> getUserByUsername(@PathVariable String username) {
		return service.getUserByUsername(username);
	}
	
	@GetMapping("/history")
	public ResponseEntity<?> getHistory() {
		return service.getHistory();
	}
	
	@PutMapping("/update/{username}")
	public ResponseEntity<?> updateUser(@PathVariable String username, @RequestBody Map<String, Object> userDetails) throws Exception {
		return service.updateUser(username, userDetails);
	}
	
	@PatchMapping("/deposit/{amount}")
	public ResponseEntity<?> deposit(@PathVariable Double amount) {
		return service.deposit(amount);
	}
	
	@PatchMapping("/withdraw/{amount}")
	public ResponseEntity<?> withdraw(@PathVariable Double amount) {
		return service.withdraw(amount);
	}
	
	@PatchMapping("/send/{receiver}/{amount}")
	public ResponseEntity<?> send(@PathVariable String receiver, @PathVariable Double amount) {
		return service.send(receiver, amount);
	}
	
	@DeleteMapping("/{username}")
	public ResponseEntity<?> deleteUser(@PathVariable String username) {
		return service.deleteUser(username);
	}
}
