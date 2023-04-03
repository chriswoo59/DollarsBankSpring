package com.dollarsbank.model;

import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Min;

@Entity
public class User implements Serializable {

	private static final long serialVersionUID = 1L;

	public static enum Role {
		ROLE_USER, ROLE_ADMIN
	}

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY) // Incrementation will use auto-increment
	private Long user_id;

	@Column(unique = true, nullable = false)
	private String username;

	@Column(nullable = false)
	private String password;

	@Column(nullable = false)
	@Email
	private String email;

	@Column(columnDefinition = "INT DEFAULT 0")
	@Min(value = 0, message = "Cannot start with a negative balance.")
	private Double total;

	@ElementCollection
	private List<String> history;

	@Enumerated(EnumType.STRING)
	private Role role;

	public User() {
		this.username = "test";
		this.password = "test";
		this.email = "test@email.com";
		this.total = 0.;
		this.history = new ArrayList<>();
		this.role = Role.ROLE_USER;
	}

	public User(String username, String password, @Email String email,
			@Min(value = 0, message = "Cannot start with a negative balance.") Double total, Role role) {
		this.username = username;
		this.password = password;
		this.email = email;
		this.total = total;
		this.history = new ArrayList<>();
		this.role = role;
	}

	public Long getUser_id() {
		return user_id;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public Double getTotal() {
		return total;
	}

	public void setTotal(Double total) {
		this.total = total;
	}

	public List<String> getHistory() {
		return history;
	}

	public void log(String text) {
		this.history.add(  "(" + LocalDateTime.now() + "):  " + text + ". Updated total: " + this.total);
	}

	public Role getRole() {
		return role;
	}

	public void setRole(Role role) {
		this.role = role;
	}

	@Override
	public String toString() {
		return "User [user_id=" + user_id + ", username=" + username + ", password=" + password + ", email=" + email
				+ ", total=" + total + ", history=" + history + "]";
	}

}
