package com.cos.security1.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.cos.security1.config.oauth.PrincipalOauth2UserService;

@Configuration
@EnableWebSecurity		// 스프링 시큐리티 필터가 스프링 필터체인에 등록한다.
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)	// secured 어노테이션 활성화 / preAuthorize, postAuthorize 어노테이션 활성화
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private PrincipalOauth2UserService principalOauth2UserService;

	// 해당 메서드의 리턴되는 오브젝트를 Ioc로 등록해준다.
	@Bean
	public BCryptPasswordEncoder encodePwd() {
		return new BCryptPasswordEncoder();
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable();
		http.authorizeRequests()
			.antMatchers("/user/**").authenticated()	// user로 가면 인증을 해야하고 manager로 가면 admin또는 manger 권한이 필요하고
			.antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
			.antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")	// admin으로 가면 admin권한이 필요하고
			.anyRequest().permitAll()									// 나머지는 모든 권한이 허용
			.and()
			.formLogin()
			.loginPage("/loginForm")
			.loginProcessingUrl("/login")	// /login 주소가 호출이 되면 시큐리티가 낚아채서 대신 로그인을 진행해준다.
			.defaultSuccessUrl("/")
			.and()
			.oauth2Login()
			.loginPage("/loginForm")	// 구글 로그인이 완료된 뒤의 후처리가 필요함.
			.userInfoEndpoint()
			.userService(principalOauth2UserService);	// Tip) 코드를 받는게 아니라 엑세스토큰+사용자프로필정보를 바로 받음
// 1.코드받기(인증)  2.엑세스토큰(권한)  3.사용자프로필 정보를 가져와서  4.그 정보를 토대로 회원가입을 자동으로 진행시키기도 함
// 4-2.(이메일,전화번호,이름,아이디)쇼핑몰 -> (집주소),백화점몰 -> (vip등급,일반등급)
	}									
}
