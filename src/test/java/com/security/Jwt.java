package com.security;

import com.security.dao.UserDao;
import com.security.domain.User;
import com.security.util.JwtUtil;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import java.util.Optional;

@RunWith(SpringRunner.class)
@SpringBootTest
public class Jwt {
    @Autowired
    UserDao userDao;
    @Autowired
    JwtUtil jwtUtil;
    @Test
    public void jwtTest() {
        for (User user : userDao.findAll()){
            System.out.println(jwtUtil.createAccessToken(user));
            System.out.println(jwtUtil.createRefreshToken(user));
            System.out.println();
        }
    }
}
