package security.jwt;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import security.jwt.domain.MemberForm;
import security.jwt.service.MemberService;

import javax.annotation.PostConstruct;

@SpringBootApplication
public class JwtApplication {

	public static void main(String[] args) {
		SpringApplication.run(JwtApplication.class, args);
	}

	@Autowired
	MemberService memberService;

	@PostConstruct
	public void init() {
		MemberForm form = MemberForm.builder()
				.username("test")
				.password("1234")
				.name("테스트 계정")
				.build();

		memberService.signUp(form);
	}

}
