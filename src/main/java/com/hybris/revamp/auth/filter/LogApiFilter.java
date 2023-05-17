package com.hybris.revamp.auth.filter;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingRequestWrapper;
import org.springframework.web.util.ContentCachingResponseWrapper;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
public class LogApiFilter extends OncePerRequestFilter
{
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
			FilterChain chain) throws ServletException, IOException
	{
		// chain執行chain的下一個filter
		chain.doFilter(request, response);

		// 印header
		this.logAPI(request, response);

		// 印Body
		this.logBody(request, response);
	}

	private void logAPI(HttpServletRequest request, HttpServletResponse response) {
		int httpStatus = response.getStatus();
		String httpMethod = request.getMethod();
		String uri = request.getRequestURI();
		String params = request.getQueryString();

		if (params != null) {
			uri += "?" + params;
		}
		log.info("{}", String.join(" ", String.valueOf(httpStatus), httpMethod, uri));
	}

	private void logBody(HttpServletRequest request, HttpServletResponse response) {
		// request.getInputStream()拿body里面的內容只能被獲取一次,因為通常也只會取一次，但有些情境(e.g.filter)就會需要取多次
		// Wrapper可以多次拿body
		ContentCachingRequestWrapper requestWrapper = new ContentCachingRequestWrapper(request);
		ContentCachingResponseWrapper responseWrapper = new ContentCachingResponseWrapper(response);
		// 後來被security的filter和執行方法先拿走了，所以現在requestBody沒有值了
		String requestBody = getContent(requestWrapper.getContentAsByteArray());
		log.info("Request: {}", requestBody);

		String responseBody = getContent(responseWrapper.getContentAsByteArray());
		log.info("Response: {}", responseBody);

	}

	private String getContent(byte[] content) {
		String body = new String(content);
		return body.replaceAll("[\n\t]", "");
	}


}
