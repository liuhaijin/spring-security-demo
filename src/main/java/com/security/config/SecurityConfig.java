package com.security.config;

import java.io.PrintWriter;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.fasterxml.jackson.databind.ObjectMapper;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
			.anyRequest()
			.authenticated()
			.and()
			.formLogin()
			.loginProcessingUrl("/doLogin")
			.successHandler((req, res, authentication) -> {
				Object principal = authentication.getPrincipal();
				res.setContentType("application/json;charset=utf-8");
				PrintWriter out = res.getWriter();
				out.write(new ObjectMapper().writeValueAsString(principal));
				out.flush();
				out.close();
			})
			.failureHandler((req, res, e) -> {
				res.setContentType("application/json;charset=utf-8");
			    PrintWriter out = res.getWriter();
			    out.write(e.getMessage());
			    out.flush();
			    out.close();
			})
			.permitAll()
			.and()
            .logout()
            .logoutUrl("/logout")
            .logoutSuccessHandler((req, resp, authentication) -> {
                resp.setContentType("application/json;charset=utf-8");
                PrintWriter out = resp.getWriter();
                out.write("注销成功");
                out.flush();
                out.close();
            })
            .permitAll()
			.and()
			.csrf().disable()
			.exceptionHandling()
			.authenticationEntryPoint((req, res, authException) -> {
	            res.setContentType("application/json;charset=utf-8");
	            PrintWriter out = res.getWriter();
	            out.write("尚未登录，请先登录");
	            out.flush();
	            out.close();
			});
	}
	
    @Bean
    PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.inMemoryAuthentication()
			.withUser("javaboy")
			.password("123")
			.roles("admin");
	}
	
	@Override
	public void configure(WebSecurity web) throws Exception {
		web.ignoring().antMatchers("/js/**", "/css/**","/images/**");
	}	
	

}
