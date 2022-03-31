package com.cos.security1.config.oauth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;

@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;
	
	@Autowired
	private UserRepository userRepository;

	// 구글로부터 받은 userRequest 데이터에 대한 후처리되는 함수
	// 함수 종료시 @AuthenticationPrincipal 어노테이션이 만들어진다.
	// 아래거 오버라이드 한 이유는 1. 맨밑에 PrincipalDetails(userEntity, oauth2User.getAttributes()) 를 묶기 위해서
	// 2. OAuth로 진행했을때 회원가입을 강제로 진행시키기 위해
	@Override
	public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
		System.out.println("userRequest :  " + userRequest.getClientRegistration()); // registrationId로 어떤 OAuth로 로그인했는지 확인가능
		System.out.println("userRequest :  " + userRequest.getAccessToken().getTokenValue());

		OAuth2User oauth2User = super.loadUser(userRequest);
		// 구글로그인 버튼 클릭 -> 구글로그인창 -> 로그인을 완료 -> code를 리턴(OAuth-Client 라이브러리) -> AccessToken 요청 ->
		// userRequest 정보 -> loadUser함수 호출 -> 구글로부터 회원프로필 받아준다.
		System.out.println("userRequest :  " + oauth2User.getAttributes());

		// 회원가입을 강제로 진행해볼예정
		String provider = userRequest.getClientRegistration().getClientId();	// google
		String providerId = oauth2User.getAttribute("sub");
		String username = provider+"_"+providerId;	// google_109742856182916427686
		String password = bCryptPasswordEncoder.encode("겟인데어");
		String email = oauth2User.getAttribute("email");
		String role = "ROLE_USER";
		
		User userEntity = userRepository.findByUsername(username);
		
		if(userEntity == null) {
			System.out.println("구글 로그인이 최초입니다.");
			userEntity = User.builder()
					.username(username)
					.password(password)
					.email(email)
					.role(role)
					.provider(providerId)
					.providerId(providerId)
					.build();
			userRepository.save(userEntity);
		}else {
			System.out.println("구글 로그인을 이미 한적이 있습니다. 당신은 회원가입이 되어 있습니다.");
		}
		
		
		// 위의 정보를 토대로 회원가입을 강제로 진행해볼예정

		return new PrincipalDetails(userEntity, oauth2User.getAttributes());
	}
}
