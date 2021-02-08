package com.security.config;

import java.io.PrintWriter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.service.UserService;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	
	@Autowired
	UserService userService;
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
			.antMatchers("/admin/**").hasRole("admin")
			.antMatchers("/user/**").hasRole("user")
			.anyRequest().authenticated()
			.and()
			.formLogin()
			.loginProcessingUrl("/doLogin")
			.successHandler(successHandler())
			.failureHandler(failureHandler())
			.permitAll()
			.and()
            .logout()
            .logoutUrl("/logout")
            .logoutSuccessHandler(logoutSuccessHandler())
            .permitAll()
			.and()
			.csrf().disable()
			.exceptionHandling()
			.authenticationEntryPoint(authenticationEntryPoint());
	}

	private AuthenticationEntryPoint authenticationEntryPoint() {
		return (req, res, authException) -> {
		    res.setContentType("application/json;charset=utf-8");
		    PrintWriter out = res.getWriter();
		    out.write("尚未登录，请先登录");
		    out.flush();
		    out.close();
		};
	}

	private LogoutSuccessHandler logoutSuccessHandler() {
		return (req, resp, authentication) -> {
		    resp.setContentType("application/json;charset=utf-8");
		    PrintWriter out = resp.getWriter();
		    out.write("注销成功");
		    out.flush();
		    out.close();
		};
	}

	private AuthenticationFailureHandler failureHandler() {
		return (req, res, e) -> {
			res.setContentType("application/json;charset=utf-8");
		    PrintWriter out = res.getWriter();
		    out.write(e.getMessage());
		    out.flush();
		    out.close();
		};
	}

	private AuthenticationSuccessHandler successHandler() {
		return (req, res, authentication) -> {
			Object principal = authentication.getPrincipal();
			res.setContentType("application/json;charset=utf-8");
			PrintWriter out = res.getWriter();
			out.write(new ObjectMapper().writeValueAsString(principal));
			out.flush();
			out.close();
		};
	}
	
	@Bean
	RoleHierarchy roleHierarchy() {
		RoleHierarchyImpl hierarchy = new RoleHierarchyImpl();
		hierarchy.setHierarchy("ROLE_admin > ROLE_user");
		return hierarchy;
	}
	
    @Bean
    PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(userService);
	}
	
	@Override
	public void configure(WebSecurity web) throws Exception {
		web.ignoring().antMatchers("/js/**", "/css/**","/images/**");
	}	
	

}
