package com.security;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.context.junit4.SpringRunner;

import com.security.dao.UserDao;
import com.security.domain.Role;
import com.security.domain.User;

 
@RunWith(SpringRunner.class)
@SpringBootTest
public class AddData {
	@Autowired
	UserDao userDao;
	@Test
	public void contextLoads() {
	    User u1 = new User();
	    u1.setUsername("javaboy");
	    u1.setPassword(new BCryptPasswordEncoder().encode("123"));
	    u1.setAccountNonExpired(true);
	    u1.setAccountNonLocked(true);
	    u1.setCredentialsNonExpired(true);
	    u1.setEnabled(true);
	    List<Role> rs1 = new ArrayList<>();
	    Role r1 = new Role();
	    r1.setName("ROLE_admin");
	    r1.setNameZh("管理员");
	    rs1.add(r1);
	    u1.setRoles(rs1);
	    userDao.save(u1);
	    User u2 = new User();
	    u2.setUsername("江南一点雨");
	    u2.setPassword(new BCryptPasswordEncoder().encode("123"));
	    u2.setAccountNonExpired(true);
	    u2.setAccountNonLocked(true);
	    u2.setCredentialsNonExpired(true);
	    u2.setEnabled(true);
	    List<Role> rs2 = new ArrayList<>();
	    Role r2 = new Role();
	    r2.setName("ROLE_user");
	    r2.setNameZh("普通用户");
	    rs2.add(r2);
	    u2.setRoles(rs2);
	    userDao.save(u2);
	}
	
	@Test
	public void delete() {
		userDao.deleteAll();
	}

	@Test
	public void updatePassword() {
		for (User user : userDao.findAll()){
			System.out.println(user);
		}
	}

	public static void main(String[] args) {
		System.out.println(new BCryptPasswordEncoder(10).encode("123"));
		System.out.println(new BCryptPasswordEncoder(10).encode("123"));
		System.out.println(new BCryptPasswordEncoder(10).encode("123"));
	}
}
