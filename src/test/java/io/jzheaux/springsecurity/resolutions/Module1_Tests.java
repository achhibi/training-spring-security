package io.jzheaux.springsecurity.resolutions;

import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.MockMvcPrint;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.data.repository.CrudRepository;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.introspection.NimbusOpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.stereotype.Repository;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.reactive.function.client.WebClient;

import javax.persistence.Entity;
import javax.persistence.ManyToOne;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import static io.jzheaux.springsecurity.resolutions.ReflectionSupport.getConstructor;
import static io.jzheaux.springsecurity.resolutions.ReflectionSupport.getDeclaredFieldByType;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

@RunWith(SpringRunner.class)
@AutoConfigureMockMvc(print=MockMvcPrint.NONE)
@SpringBootTest
public class Module1_Tests {

	@Autowired
	MockMvc mvc;

	@Autowired(required = false)
	UserDetailsService userDetailsService;

	@Autowired(required = false)
	CrudRepository<User, UUID> users;

	@Autowired
	ApplicationContext context;

	@Autowired
	ResolutionController resolutionController;

	@TestConfiguration
	static class WebClientPostProcessor implements DisposableBean {
		MockWebServer userEndpoint = new MockWebServer();

		@Override
		public void destroy() throws Exception {
			this.userEndpoint.shutdown();
		}

		@Autowired(required = false)
		void postProcess(WebClient.Builder web) throws Exception {
			web.baseUrl(this.userEndpoint.url("").toString());
		}

		@Bean
		MockWebServer userEndpoint() {
			this.userEndpoint.setDispatcher(new Dispatcher() {
				@Override
				public MockResponse dispatch(RecordedRequest recordedRequest) {
					MockResponse response = new MockResponse().setResponseCode(200);
					String path = recordedRequest.getPath();
					switch(path) {
						case "/user/user/fullName":
							return response.setBody("User Userson");
						case "/user/hasread/fullName":
							return response.setBody("Has Read");
						case "/user/haswrite/fullName":
							return response.setBody("Has Write");
						case "/user/admin/fullName":
							return response.setBody("Admin Adminson");
						default:
							return response.setResponseCode(404);
					}
				}
			});
			return this.userEndpoint;
		}
	}

	@TestConfiguration
	static class TestConfig {

		@ConditionalOnProperty("spring.security.oauth2.resourceserver.jwt.issuer-uri")
		@Bean
		JwtDecoder jwtDecoder() {
			return NimbusJwtDecoder
					.withJwkSetUri("https://idp.example.org/jwks")
					.build();
		}

		@ConditionalOnProperty("spring.security.oauth2.resourceserver.opaquetoken.introspection-uri")
		@Bean
		JwtDecoder interrim() {
			return token -> {
				throw new BadJwtException("bad jwt");
			};
		}

		@ConditionalOnProperty("spring.security.oauth2.resourceserver.opaquetoken.introspection-uri")
		@ConditionalOnMissingBean
		@Bean
		OpaqueTokenIntrospector introspector(OAuth2ResourceServerProperties properties) {
			return new NimbusOpaqueTokenIntrospector(
					properties.getOpaquetoken().getIntrospectionUri(),
					properties.getOpaquetoken().getClientId(),
					properties.getOpaquetoken().getClientSecret());
		}

	}

	/**
	 * Add the appropriate Spring Boot starter dependency
	 */
	@Test
	public void task_1() throws Exception {
		assertNotNull(
				"Task 1: Couldn't find a `UserDetailsService` in the application context. " +
						"Make sure that you've removed the `SecurityAutoConfiguration` exclusion from teh `@SpringBootApplication` annotation.",
				this.userDetailsService);

		MvcResult result = this.mvc.perform(get("/resolutions"))
				.andReturn();

		assertEquals(
				"Task 1: The `/resolutions` endpoint isn't protected. " +
						"Make sure that you've removed the `SecurityAutoConfiguration` exclusion from the `@SpringBootApplication` annotation.",
				result.getResponse().getStatus(), 401);

		String wwwAuthenticate = result.getResponse().getHeader(HttpHeaders.WWW_AUTHENTICATE);
		assertNotNull(
				"Task 1: The `/resolutions` response is missing the `WWW-Authenticate` response header. " +
						"Make sure that you've removed the `SecurityAutoConfiguration` exclusion from the `@SpringBootApplication` annotation.",
				wwwAuthenticate);

		assertTrue(
				"Task 1: The `/resolutions` response's `WWW-Authenticate` header is [" + wwwAuthenticate + "], but `Basic` is what is expected at this point in the project. " +
						"Make sure that you've removed the `SecurityAutoConfiguration` exclusion from the `@SpringBootApplication` annotation.",
				wwwAuthenticate.startsWith("Basic"));
	}

	@Test
	public void task_2() throws Exception {
		// add InMemoryUserDetailsManager
		task_1();
		String failureMessage = assertUserDetailsService(InMemoryUserDetailsManager.class);
		if (failureMessage != null) {
			fail("Task 2: " + failureMessage);
		}

		MvcResult result = this.mvc.perform(get("/resolutions")
				.with(httpBasic("user", "password")))
				.andReturn();

		assertEquals(
				"Task 2: The `/resolutions` response failed to authorize user/password as the username and password. " +
						"Make sure that your `UserDetailsService` is wired with a password of `password`.",
				result.getResponse().getStatus(), 200);
	}

	@Test
	public void task_3() throws Exception {
		// create User
		task_1();
		Entity userEntity = User.class.getAnnotation(Entity.class);

		assertTrue(
				"Task 3: Since you are going to be using `JdbcUserDetailsManager` to retrieve users in an upcoming step, " +
						"the Users class needs to be annotated with `@javax.persistence.Entity(name=\"users\")` since that's the table name that the " +
						"manager expects",
				userEntity != null && "users".equals(userEntity.name()));

		assertNotNull(
				"Task 3: Since you are going to be using `JdbcUserDetailsManager` to retrieve users in an upcoming step, " +
						"the `Users` class needs a JPA field mapped to the `username` column.",
				ReflectedUser.usernameColumnField);

		assertNotNull(
				"Task 3: Since you are going to be using `JdbcUserDetailsManager` to retrieve users in an upcoming step, " +
						"the `Users` class needs a JPA field mapped to the `password` column.",
				ReflectedUser.passwordColumnField);

		assertNotNull(
				"Task 3: Since you are going to be using `JdbcUserDetailsManager` to retrieve users in an upcoming step, " +
						"the `Users` class needs a JPA field mapped to the `enabled` column.",
				ReflectedUser.enabledColumnField);
	}

	@Test
	public void task_4() throws Exception {
		// create UserRepository
		task_3(); // check that everything from Task 3 still holds
		assertNotNull(
				"Task 4: Make sure that your `UserRepository` is annotated with " + Repository.class,
				UserRepository.class.getAnnotation(Repository.class));

		assertNotNull(
				"Task 4: Make sure that your `UserRepository` is extending `CrudRepository<User,UUID>`",
				this.users);
	}

	@Test
	public void task_5() throws Exception {
		// add users to database
		task_4(); // make sure everything from task_4 still holds
		Iterable<User> users = this.users.findAll();
		Map<String, ReflectedUser> usersByUsername = StreamSupport.stream(users.spliterator(), false)
				.map(ReflectedUser::new)
				.collect(Collectors.toMap(ReflectedUser::getUsername, Function.identity()));

		ReflectedUser user = usersByUsername.get("user");
		assertNotNull(
				"Task 5: To ensure that future tests work, make sure that that `UserRepository` has at least a user " +
						"whose username is `user`",
				user);

		String storedPassword = user.getPassword();
		assertNotEquals(
				"Task 5: Make sure that the password you add to the database is encoded",
				"password", storedPassword);
		PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
		assertTrue(
				"Task 5: Make sure that you are using the default password encoder to encode the user's password " +
						"before persisting. The default password encoder is `PasswordEncoderFactories.createDelegatingPasswordEncoder`",
				encoder.matches("password", storedPassword));
	}

	@Test
	public void task_6() throws Exception {
		// publish JdbcUserDetailsManager
		task_5();
		String failureMessage = assertUserDetailsService(JdbcUserDetailsManager.class);
		if (failureMessage != null) {
			fail("Task 6: " + failureMessage);
		}

		MvcResult result = this.mvc.perform(get("/resolutions")
				.with(httpBasic("user", "password")))
				.andReturn();

		assertEquals(
				"Task 6: The `/resolutions` endpoint failed to authorize user/password as the username and password. " +
						"Make sure that you're adding the appropriate roles to the user -- since we haven't added authority yet, " +
						"they should be added manually when constructing the `JdbcUserDetailsManager`.",
				result.getResponse().getStatus(), 200);
	}

	@Test
	public void task_7() throws Exception {
		// add UserAuthority
		task_6();
		Entity authorityEntity = UserAuthority.class.getAnnotation(Entity.class);

		assertTrue(
				"Task 7: Since you are using `JdbcUserDetailsManager` to retrieve users, " +
						"the `UserAuthority` class needs to be annotated with `@Entity(name=\"authorities\")` since " +
						"that's the table name that the manager expects by default",
				authorityEntity != null && "authorities".equals(authorityEntity.name()));

		assertNotNull(
				"Task 7: Since you are going to be using `JdbcUserDetailsManager` to retrieve users in an upcoming step, " +
						"the `UserAuthority` class needs a JPA field mapped to the `authority` column.",
				ReflectedUserAuthority.authorityColumnField);

		assertNotNull(
				"Task 7: Since you are going to be using `JdbcUserDetailsManager` to retrieve users in an upcoming step, " +
						"the `UserAuthority` class needs a `username` column. JPA can do this with the `@JoinColumn` annotation on a " +
						"field of type `User`.",
				ReflectedUserAuthority.usernameColumnField);

		assertEquals(
				"Task 7: Let's please keep the `User` field and the JPA field for the `username` column the same." +
						"This can be done by introducing a field of ype `User` that uses a `@ManyToOne` annotation and a `@JoinColumn` annotation " +
						"specifying a `name` and `referencedColumnName` of `username`.",
				ReflectedUserAuthority.userField, ReflectedUserAuthority.usernameColumnField);

		assertNotNull(
				"Task 7: Make sure that the `User` field is annotated with `@ManyToOne`",
				ReflectedUserAuthority.userField.getAnnotation(ManyToOne.class));

		assertNotNull(
				"Task 7: Make sure that you've updated `User` to declare its bi-directional relationship to `UserAuthority`. " +
						"There should be a field annotated with `@OneToMany` with a collection of type `UserAuthority`.",
				ReflectedUser.userAuthorityCollectionField);

		assertNotNull(
				"Task 7: Make sure to add a `grantAuthority` method to `User`",
				ReflectedUser.grantAuthorityMethod);

		String authority = UUID.randomUUID().toString();
		ReflectedUser user = ReflectedUser.newInstance();
		try {
			user.grantAuthority(authority);
		} catch (Exception e) {
			fail("Task 7: Tried to grant an authority, but experienced an error: " + e);
		}

		try {
			Collection<UserAuthority> authorities = user.getUserAuthorities();
			assertTrue(
					"Task 7: After granting an authority, the authorities list is still empty. Make sure you are adding " +
							"an authority to your `User`'s authority list when `grantAuthority` is called.",
					authorities.size() > 0);

			Optional<ReflectedUserAuthority> hasRoleUser = authorities.stream()
					.map(ReflectedUserAuthority::new)
					.filter(a -> authority.equals(a.getAuthority()))
					.findFirst();
			assertTrue(
					"Task 7: After granting an authority, the authorities list does not have a matching `UserAuthority`" +
							". Make sure you are setting the authority's value to be what is passed in to " +
							"`grantAuthority`",
					hasRoleUser.isPresent());

			ReflectedUserAuthority userAuthority = hasRoleUser.get();
			ReflectedUser userFromUserAuthority = new ReflectedUser(userAuthority.getUser());
			assertEquals(
					"Task 7: Make sure that the `User` stored in `UserAuthority` matches the `User` instance on which " +
							"`grantAuthority` was called.",
					user.user, userFromUserAuthority.user);
		} catch (Exception e) {
			fail(
					"Task 7: Make sure that the authorities property in `User` is called `userAuthorities`. While not strictly " +
							"necessary, with simplify future steps.");
		}
	}

	@Test
	public void task_8() throws Exception {
		task_7();
		// add additional users with authorities

		try {
			UserDetails userDetails = this.userDetailsService.loadUserByUsername("hasread");
			Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();
			assertTrue(
					"Task 8: Make sure the `hasread` user has the `resolution:read` authority",
					authorities.contains(new SimpleGrantedAuthority("resolution:read")));
			assertFalse(
					"Task 8: Make sure the `hasread` user doesn't not have the `resolution:write` authority",
					authorities.contains(new SimpleGrantedAuthority("resolution:write")));
		} catch (UsernameNotFoundException e) {
			fail(
					"Task 8: Make sure to add a user `hasread` with an encoded password of `password`");
		}

		try {
			UserDetails userDetails = this.userDetailsService.loadUserByUsername("haswrite");
			Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();
			assertTrue(
					"Task 8: Make sure the `haswrite` user has the `resolution:write` authority",
					authorities.contains(new SimpleGrantedAuthority("resolution:write")));
			assertFalse(
					"Task 8: Make sure the `haswrite` user doesn't not have the `resolution:read` authority",
					authorities.contains(new SimpleGrantedAuthority("resolution:read")));
		} catch (UsernameNotFoundException e) {
			fail(
					"Task 8: Make sure to add a user `haswrite` with an encoded password of `password`");
		}
	}

	@Test
	public void task_9() throws Exception {
		// add simple authorization
		task_8();

		MvcResult result = this.mvc.perform(get("/resolutions")
				.with(httpBasic("hasread", "password")))
				.andReturn();

		assertNotEquals(
				"Task 9: Authentication failed for user `hasread`. Make sure that the password is " +
				"set to 'password'.",
				401, result.getResponse().getStatus());

		assertNotEquals(
				"Task 9: Authorization failed for user `hasread`, which has the 'resolution:read' permission. Please " +
				"check your security configuration to make sure that `/resolutions` is only requiring the 'resolution:read' permission.",
				403, result.getResponse().getStatus());

		assertEquals(
				"Task 9: `/resolutions` endpoint responded with " + result.getResponse().getStatus() + " " +
				"instead of the expected 200",
				200, result.getResponse().getStatus());

		result = this.mvc.perform(post("/resolution")
				.content("my resolution")
				.with(csrf())
				.with(httpBasic("hasread", "password")))
				.andReturn();

		assertEquals(
				"Task 9: The `/resolution` POST endpoint allowed `hasread` even though it only was " +
						"granted 'resolution:read'. Please check your security configuration to make sure that `/resolution` POST is " +
						"requiring the 'resolution:write' permission",
				403, result.getResponse().getStatus());

		result = this.mvc.perform(post("/resolution")
				.content("my resolution")
				.with(csrf())
				.with(httpBasic("haswrite", "password")))
				.andReturn();

		assertNotEquals(
				"Task 9: Authentication failed for user `haswrite`. Make sure that the password is " +
				"set to 'password'.",
				401, result.getResponse().getStatus());

		assertNotEquals(
				"Task 9: Authorization failed for user `haswrite`, which has the 'resolution:write' permission. Please " +
				"check your security configuration to make sure that `/resolution` POST is only requiring the 'resolution:write' permission.",
				403, result.getResponse().getStatus());

		assertEquals(
				"Task 9: The `/resolution` POST endpoint responded with " + result.getResponse().getStatus() + " " +
				"instead of the expected 200",
				200, result.getResponse().getStatus());
	}

	@Test
	public void task_10() throws Exception {
		// add User copy constructor
		task_9();
		assertNotNull(
				"Task 10: Couldn't find a copy constructor in `User` class.",
				ReflectedUser.copyConstructor);

		ReflectedUser user = new ReflectedUser(this.users.findAll().iterator().next());
		try {
			ReflectedUser copy = ReflectedUser.copiedInstance(user);
			assertEquals(
					"Task 10: The usernames of the original and its copy are different.",
					user.getUsername(),
					copy.getUsername());

			assertEquals(
					"Task 10: The passwords of the original and its copy are different.",
					user.getPassword(),
					copy.getPassword());

			Collection<String> userAuthorities = user.getUserAuthorities().stream()
					.map(ua -> new ReflectedUserAuthority(ua).getAuthority())
					.collect(Collectors.toList());
			Collection<String> copyAuthorities = copy.getUserAuthorities().stream()
					.map(ua -> new ReflectedUserAuthority(ua).getAuthority())
					.collect(Collectors.toList());
			assertEquals(
					"Task 10: The authorities of the original and its copy are different.",
					userAuthorities,
					copyAuthorities);
		} catch (Exception e) {
			fail("Task 10: `User`'s copy constructor threw an exception: " + e);
		}
	}

	@Test
	public void task_11() throws Exception {
		// add custom UserDetailsService
		task_1();

		UserDetailsService userDetailsService = null;
		if (this.userDetailsService instanceof UserRepositoryUserDetailsService) {
			userDetailsService = this.userDetailsService;
		} else if (UserDetailsService.class.isAssignableFrom(UserRepositoryUserDetailsService.class)){
			Constructor<?> defaultConstructor = getConstructor(UserRepositoryUserDetailsService.class);
			if (defaultConstructor != null) {
				userDetailsService = (UserDetailsService) defaultConstructor.newInstance();
			} else {
				Constructor<?> userRepositoryConstructor =
						getConstructor(UserRepositoryUserDetailsService.class, UserRepository.class);
				if (userRepositoryConstructor != null) {
					userDetailsService = (UserDetailsService) userRepositoryConstructor.newInstance(this.users);
				}
			}
		}

		assertNotNull(
				"Task 11: Could not construct an instance of type `UserRepositoryUserDetailsService`. " +
						"Make sure that it either has a default constructor or one that takes as `UserRepository` instance",
				userDetailsService);

		try {
			userDetailsService.loadUserByUsername(UUID.randomUUID().toString());
			fail("Task 11: Make sure your custom `UserDetailsService` throws a `UsernameNotFoundException` when it can't find a user" );
		} catch (UsernameNotFoundException expected) {
			// ignoring
		} catch (Exception e) {
			fail("Task 11: Make sure your custom `UserDetailsService` throws a `UsernameNotFoundException` when it can't find a user" );
		}
	}

	@Test
	public void task_12() throws Exception {
		task_11();

		Field userRepositoryField = getDeclaredFieldByType(UserRepositoryUserDetailsService.class, UserRepository.class);
		assertNotNull(
				"Task 12: For this exercise make sure that your custom `UserDetailsService` implementation is delegating to " +
						"a `UserRepository` instance",
				userRepositoryField);
	}

	@Test
	public void task_13() throws Exception {
		task_12();

		String failureMessage = assertUserDetailsService(UserRepositoryUserDetailsService.class);
		if (failureMessage != null) {
			fail("Task 13: " + failureMessage);
		}

		UserDetails user = this.userDetailsService.loadUserByUsername("user");

		assertTrue(
				"Task 13: The object returned from a custom `UserDetailsService` should be castable to your custom " +
						"`User` type.",
				User.class.isAssignableFrom(user.getClass()));

		assertTrue(
				"Task 13: The object returned from a custom `UserDetailsService` must be castable to `UserDetails`",
				UserDetails.class.isAssignableFrom(user.getClass()));

		MvcResult result = this.mvc.perform(get("/resolutions")
				.with(httpBasic("user", "password")))
				.andReturn();

		assertEquals(
				"Task 13: The `/resolutions` response failed to authorize `user`/`password` as the username and password. " +
						"Make sure that your custom `UserDetailsService` is wired with a password of `password`.",
				result.getResponse().getStatus(), 200);

		result = this.mvc.perform(get("/resolutions")
				.with(httpBasic("haswrite", "password")))
				.andReturn();

		assertEquals(
				"Task 13: The `/resolutions` endpoint authorized `haswrite`/`password` even though it does not have the `resolution:read` permission.",
				result.getResponse().getStatus(), 403);

		result = this.mvc.perform(post("/resolution")
				.content("my resolution")
				.with(csrf())
				.with(httpBasic("hasread", "password")))
				.andReturn();

		assertEquals(
				"Task 13: The `/resolution` `POST` endpoint authorized `hasread`/`password` even though `hasread` only has the `resolution:read` permission.",
				result.getResponse().getStatus(), 403);

		result = this.mvc.perform(post("/resolution")
				.content("my resolution")
				.with(csrf())
				.with(httpBasic("haswrite", "password")))
				.andReturn();

		assertEquals(
				"Task 13: The `/resolution` `POST` response failed to authorize `haswrite`/`password` even though `haswrite` has the `resolution:write` password.",
				result.getResponse().getStatus(), 200);
	}

	@Test
	public void task_14() throws Exception {
		task_13();

		Authentication haswrite = token("haswrite");
		Method make = method(ResolutionController.class, "make", String.class, String.class);
		assertNotNull(
				"Task 14: Please add the current logged-in user's `username` as a method parameter, including the `@CurrentUsername` annotation." +
						" While technically any method parameter can " +
						"contain user information, this test expects it to be the first parameter",
				make);
		SecurityContextHolder.getContext().setAuthentication(haswrite);
		try {
			ReflectedUser haswriteUser = new ReflectedUser((User) haswrite.getPrincipal());
			Resolution resolution =
					(Resolution) make.invoke(this.resolutionController, haswriteUser.getUsername(), "my resolution");
			assertEquals(
					"Task 14: When making a resolution, the user attached to the resolution does not match the logged in user. " +
							"Make sure you are passing the id of the currently logged-in user to `ResolutionRepository`",
					resolution.getOwner(), haswriteUser.getUsername());
		} catch (Exception e) {
			fail(
					"Task 14: `ResolutionController#make threw an exception: " + e);
		} finally {
			SecurityContextHolder.clearContext();
		}
	}

	private enum UserDetailsServiceVerifier {
		INMEMORY(InMemoryUserDetailsManager.class, Module1_Tests::assertInMemoryUserDetailsService),
		JDBC(JdbcUserDetailsManager.class, Module1_Tests::assertJdbcUserDetailsService),
		CUSTOM(UserRepositoryUserDetailsService.class, Module1_Tests::assertCustomUserDetailsService);

		Class<?> clazz;
		Function<UserDetailsService, String> verifier;

		UserDetailsServiceVerifier(Class<?> clazz,
								   Function<UserDetailsService, String> verifier) {
			this.clazz = clazz;
			this.verifier = verifier;
		}

		String verify(UserDetailsService userDetailsService) {
			return this.verifier.apply(userDetailsService);
		}

		static UserDetailsServiceVerifier fromClass(Class<?> clazz) {
			for (UserDetailsServiceVerifier verifier : values()) {
				if (verifier.clazz.isAssignableFrom(clazz)) {
					return verifier;
				}
			}
			throw new NoSuchElementException("error!");
		}
	}

	private String assertUserDetailsService(Class<?> simplestAllowedUserDetailsService) {
		UserDetailsServiceVerifier minimum = UserDetailsServiceVerifier.fromClass(simplestAllowedUserDetailsService);

		try {
			UserDetailsServiceVerifier verifier = UserDetailsServiceVerifier.fromClass(this.userDetailsService.getClass());
			if (verifier.ordinal() < minimum.ordinal()) {
				return "The `UserDetailsService` bean is not of type `" + minimum.clazz.getName() + "`. Please double-check " +
						"the type you are returning for your `UserDetailsService` `@Bean`.";
			}
			return verifier.verify(this.userDetailsService);
		} catch (NoSuchElementException e) {
			return "Could not find a `UserDetailsService` of the right type. " +
					"Please double-check the `@Bean` that you are exposing";
		}
	}

	static String assertInMemoryUserDetailsService(UserDetailsService userDetailsService) {
		UserDetails user = userDetailsService.loadUserByUsername("user");
		if (user == null) {
			return "Make sure that your `InMemoryUserDetailsManager` is wired with a username of 'user'. " +
					"This is usually done by calling building a `User` with `User#withUsername`.";
		}

		return null;
	}

	static String assertJdbcUserDetailsService(UserDetailsService userDetailsService) {
		UserDetails user = userDetailsService.loadUserByUsername("user");
		if (user == null) {
			return "Make sure that your user database table has a user with a username of `user`.";
		}

		return null;
	}

	static String assertCustomUserDetailsService(UserDetailsService userDetailsService) {
		UserDetails user = userDetailsService.loadUserByUsername("user");
		if (user == null) {
			return "Make sure that your custom `UserDetailsService` has a user with a username of `user`. " +
					"This should be provided via the `UserRepository` which is pointing to your user database table.";
		}

		return null;
	}

	Method method(Class<?> clazz, String method, Class<?>... params) {
		try {
			return clazz.getDeclaredMethod(method, params);
		} catch (Exception e) {
			return null;
		}
	}

	Authentication token(String username) {
		UserDetails details = this.userDetailsService.loadUserByUsername(username);
		return new TestingAuthenticationToken(details, details.getPassword(),
				new ArrayList<>(details.getAuthorities()));
	}
}
