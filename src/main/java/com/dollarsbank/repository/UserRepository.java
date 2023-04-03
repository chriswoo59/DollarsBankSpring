package com.dollarsbank.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.dollarsbank.model.User;

@Repository
public interface UserRepository extends JpaRepository<User, Long>{

	public Optional<User> findByUsernameIgnoreCase(String username);
}
