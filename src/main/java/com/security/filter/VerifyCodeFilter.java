package com.security.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

@Component
public class VerifyCodeFilter extends GenericFilterBean {
	
	private String defaultFilterProcessUrl = "/doLogin";
	
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest req = (HttpServletRequest) request;
		HttpServletResponse res = (HttpServletResponse) response;
		if("POST".equalsIgnoreCase(req.getMethod()) && defaultFilterProcessUrl.equals(req.getServletPath())) {
			// 验证码验证
			String requestCaptcha = req.getParameter("code");
			String genCaptcha = (String) req.getSession().getAttribute("index_code");
			if(StringUtils.isEmpty(requestCaptcha)) {
				throw new AuthenticationServiceException("验证码不能为空!");
			}
			if (!genCaptcha.toLowerCase().equals(requestCaptcha.toLowerCase())) {
                throw new AuthenticationServiceException("验证码错误!");
            }
		}
		chain.doFilter(req, res);
	}

}
