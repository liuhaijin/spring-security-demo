package com.security.dao;

import org.springframework.data.jpa.repository.JpaRepository;

import com.security.domain.User;

public interface UserDao extends JpaRepository<User, Long> {
	User findUserByUsername(String username);
}
