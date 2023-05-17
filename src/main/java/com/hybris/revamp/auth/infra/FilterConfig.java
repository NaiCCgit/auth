package com.hybris.revamp.auth.infra;

import com.hybris.revamp.auth.filter.LogApiFilter;
import com.hybris.revamp.auth.filter.LogProcessTimeFilter;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;


@Configuration
public class FilterConfig {

	/**
	 * 寫好的filter class要註冊為Bean才會有這個元件可以用
	 * @return 不是filter本身，而是FilterRegistrationBean
	 */
	@Bean
	public FilterRegistrationBean<LogApiFilter> logApiFilter() {
		FilterRegistrationBean<LogApiFilter> bean = new FilterRegistrationBean<>();
		bean.setFilter(new LogApiFilter());
		bean.addUrlPatterns("/*");
		bean.setName("logApiFilter");
		// 執行順序
		bean.setOrder(1);

		return bean;
	}

	@Bean
	public FilterRegistrationBean<LogProcessTimeFilter> logProcessTimeFilter() {
		FilterRegistrationBean<LogProcessTimeFilter> bean = new FilterRegistrationBean<>();
		bean.setFilter(new LogProcessTimeFilter());
		bean.addUrlPatterns("/*");
		bean.setName("logProcessTimeFilter");
		bean.setOrder(0);

		return bean;
	}
}
