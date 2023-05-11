package com.hybris.revamp.auth.filter;

import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


public class LogApiFilter extends OncePerRequestFilter
{
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
			FilterChain chain) throws ServletException, IOException
	{
		chain.doFilter(request, response);

		int httpStatus = response.getStatus();
		String httpMethod = request.getMethod();
		String uri = request.getRequestURI();
		String params = request.getQueryString();

		if (params != null) {
			uri += "?" + params;
		}

		System.out.println(String.join(" ", String.valueOf(httpStatus), httpMethod, uri));
	}
}
