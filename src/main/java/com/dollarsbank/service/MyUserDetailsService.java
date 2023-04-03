package com.dollarsbank.service;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.dollarsbank.model.User;
import com.dollarsbank.repository.UserRepository;

@Service
public class MyUserDetailsService implements UserDetailsService{
	
	@Autowired
	UserRepository userRepo;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		Optional<User> user = userRepo.findByUsernameIgnoreCase(username);
		if (user == null || user.isEmpty()) {
			throw new UsernameNotFoundException(username);
		}
		return new MyUserDetails(user.get());
	}

	
}
