package com.security.config;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.domain.RespBean;
import com.security.domain.User;
import com.security.filter.LoginFilter;
import com.security.filter.VerifyCodeFilter;
import com.security.service.UserService;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	
	@Autowired
	VerifyCodeFilter verifyCodeFilter;
	
	@Autowired
	UserService userService;
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.addFilterBefore(loginFilter(), UsernamePasswordAuthenticationFilter.class);
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
	LoginFilter loginFilter() throws Exception {
	    LoginFilter loginFilter = new LoginFilter();
	    loginFilter.setAuthenticationSuccessHandler(new AuthenticationSuccessHandler() {
	        @Override
	        public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
	            response.setContentType("application/json;charset=utf-8");
	            PrintWriter out = response.getWriter();
	            User user = (User) authentication.getPrincipal();
	            user.setPassword(null);
	            RespBean ok = RespBean.ok("登录成功!", user);
	            String s = new ObjectMapper().writeValueAsString(ok);
	            out.write(s);
	            out.flush();
	            out.close();
	        }
	    });
	    loginFilter.setAuthenticationFailureHandler(new AuthenticationFailureHandler() {
	        @Override
	        public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
	            response.setContentType("application/json;charset=utf-8");
	            PrintWriter out = response.getWriter();
	            RespBean respBean = RespBean.error(exception.getMessage());
	            if (exception instanceof LockedException) {
	                respBean.setMsg("账户被锁定，请联系管理员!");
	            } else if (exception instanceof CredentialsExpiredException) {
	                respBean.setMsg("密码过期，请联系管理员!");
	            } else if (exception instanceof AccountExpiredException) {
	                respBean.setMsg("账户过期，请联系管理员!");
	            } else if (exception instanceof DisabledException) {
	                respBean.setMsg("账户被禁用，请联系管理员!");
	            } else if (exception instanceof BadCredentialsException) {
	                respBean.setMsg("用户名或者密码输入错误，请重新输入!");
	            }
	            out.write(new ObjectMapper().writeValueAsString(respBean));
	            out.flush();
	            out.close();
	        }
	    });
	    loginFilter.setAuthenticationManager(authenticationManagerBean());
	    loginFilter.setFilterProcessesUrl("/doLogin");
	    return loginFilter;
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
		web.ignoring().antMatchers("/js/**", "/css/**","/images/**", "/vercode");
	}	
	

}
