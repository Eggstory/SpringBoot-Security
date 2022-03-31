package com.cos.security1.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;

@Controller
public class IndexController {

	@Autowired
	private UserRepository userRepository;
	
	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;


	@GetMapping("/test/login")
	public @ResponseBody String testLogin(Authentication authentication,
			@AuthenticationPrincipal PrincipalDetails userDetails) {	// DI
		System.out.println("/test/login ================");
		PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
		System.out.println("authentication : "+principalDetails.getUser());
		
		System.out.println("userDetails : "+userDetails.getUser());
		return "세션정보 확인하기";
	}
		
		// 이걸 어케 활용하지... 외워야하나
		// (PrincipalDetails) authentication.getPrincipal().getUser() = @AuthenticationPrincipal PrincipalDetails.getUser()

	@GetMapping("/test/oauth/login")
	public @ResponseBody String testOAuthLogin(Authentication authentication,
			@AuthenticationPrincipal OAuth2User oauth) { // DI
		System.out.println("/test/oauth/login ================");
		OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
		System.out.println("authentication : " + oauth2User.getAttributes());
		System.out.println("oauth2User : "+oauth.getAttributes());

		return "OAuth 세션정보 확인하기";

		// PrincipalOauth2UserService.java 파일에 super.loadUser(userRequest).getAttributes()랑
		// oauth2User.getAttributes() 결과값이 동일
		
		
	}

	// login() 메소드를 안 만든 이유는 시큐리티에서 처리해주기 때문에

	@GetMapping({ "", "/" })
	public String index() {
		return "index";
	}

	
	// OAuth 로그인을 해도 PrincipalDetails
	// 일반 로그인을 해도 PrincipalDetails
									// @AuthenticationPrincipal OAuth2User oauth (google로그인일떄)
									// @AuthenticationPrincipal UserDetails userDetails (일반로그인일때)
	@GetMapping("/user")			// 아래방식은 위 두개를 PrincipalDetails(부모클래스)에다가 상속시켜서 일일이 바꿀 필요없이 만든거
	public @ResponseBody String user(@AuthenticationPrincipal PrincipalDetails principalDetails) { 
		System.out.println("principalDetails : "+principalDetails.getUser());
		return "user";
	}

	@GetMapping("/admin")
	public @ResponseBody String admin() {
		return "admin";
	}

	@GetMapping("/manager")
	public @ResponseBody String manager() {
		return "manager";
	}

	// 스프링 시큐리티가 해당주소를 낚아채감 - SecurityConfig 파일 생성 후 작동안함
	@GetMapping("/loginForm")
	public String loginForm() {
		return "loginForm";
	}

	@GetMapping("/joinForm")
	public String joinForm() {
		return "joinForm";
	}

	@PostMapping("/join")
	public String join(User user) {
		System.out.println(user);
		user.setRole("ROLE_USER");
		String rawPassword = user.getPassword();
		String encPassword = bCryptPasswordEncoder.encode(rawPassword);
		user.setPassword(encPassword);
		userRepository.save(user); // 회원가입은 잘되나 비밀번호 : 1234 => 시큐리티로 로그인을 할 수 없음
									// 이유는 패스워드가 암호화가 안되있어서
		return "redirect:/loginForm";
	}

	@Secured("ROLE_ADMIN") // 여러개 쓸거면 @PreAuthorize 사용
	@GetMapping("/info")
	public @ResponseBody String info() {
		return "개인정보";
	}

	@PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')") // 1개만 쓸거면 @secured 사용
	@GetMapping("/data")
	public @ResponseBody String data() {
		return "데이터정보";
	}

}
