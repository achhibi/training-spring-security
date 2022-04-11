package io.jzheaux.springsecurity.resolutions;

import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.MockMvcPrint;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.core.convert.converter.Converter;
import org.springframework.data.repository.CrudRepository;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.introspection.NimbusOpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.client.WebClient;

import java.lang.reflect.Field;
import java.net.URI;
import java.util.Collections;
import java.util.UUID;

import static io.jzheaux.springsecurity.resolutions.ReflectionSupport.getDeclaredFieldByColumnName;
import static io.jzheaux.springsecurity.resolutions.ReflectionSupport.getDeclaredFieldByType;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType.BEARER;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

@RunWith(SpringRunner.class)
@AutoConfigureMockMvc(print=MockMvcPrint.NONE)
@SpringBootTest
public class Module4_Tests {
    @Autowired
    MockMvc mvc;

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri:#{null}}")
    String issuerUri;

    @Value("${spring.security.oauth2.resourceserver.opaquetoken.introspection-uri:#{null}}")
    String introspectionUrl;

    @Autowired(required = false)
    JwtDecoder jwt;

    @Autowired(required = false)
    JwtAuthenticationProvider jwtAuthenticationProvider;

    @Autowired(required = false)
    OpaqueTokenIntrospector introspector;

    @Autowired(required = false)
    UserDetailsService userDetailsService;

    @Autowired(required = false)
    Converter<Jwt, AbstractAuthenticationToken> jwtAuthenticationConverter;

    @Autowired
    AuthorizationServer authz;

    @Autowired
    ResolutionController resolutionController;

    @Autowired
    ResolutionRepository resolutionRepository;

    @Autowired(required = false)
    CrudRepository<User, UUID> users;

    @Before
    public void setup() {
        assertNotNull(
                "Module 1: Could not find `UserDetailsService` in the application context; make sure to complete the earlier modules " +
                        "before starting this one", this.userDetailsService);
        assertNotNull(
                "Module 1: Could not find `UserRepository<User, UUID>` in the application context; make sure to complete the earlier modules " +
                        "before starting this one", this.users);
    }

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
    static class TestConfig implements DisposableBean, InitializingBean {
        AuthorizationServer server = new AuthorizationServer();

        @Override
        public void afterPropertiesSet() throws Exception {
            this.server.start();
        }

        @Override
        public void destroy() throws Exception {
            this.server.stop();
        }

        @ConditionalOnProperty("spring.security.oauth2.resourceserver.jwt.issuer-uri")
        @Bean
        JwtDecoder jwtDecoder(OAuth2ResourceServerProperties properties) {
            return JwtDecoders.fromOidcIssuerLocation(this.server.issuer());
        }

        @ConditionalOnProperty("spring.security.oauth2.resourceserver.opaquetoken.introspection-uri")
        @Bean
        JwtDecoder interrim() {
            return JwtDecoders.fromOidcIssuerLocation(this.server.issuer());
        }

        @ConditionalOnProperty("spring.security.oauth2.resourceserver.opaquetoken.introspection-uri")
        @ConditionalOnMissingBean
        @Bean
        OpaqueTokenIntrospector introspector(OAuth2ResourceServerProperties properties) {
            return new NimbusOpaqueTokenIntrospector(
                    this.server.introspectionUri(),
                    properties.getOpaquetoken().getClientId(),
                    properties.getOpaquetoken().getClientSecret());
        }

        @Bean
        AuthorizationServer authz() {
            return this.server;
        }
    }


    @TestConfiguration
    static class OpaqueTokenPostProcessor {
        @Autowired
        AuthorizationServer authz;

        @Autowired(required=false)
        void introspector(OpaqueTokenIntrospector introspector) throws Exception {
            NimbusOpaqueTokenIntrospector nimbus = null;
            if (introspector instanceof NimbusOpaqueTokenIntrospector) {
                nimbus = (NimbusOpaqueTokenIntrospector) introspector;
            } else if (introspector instanceof UserRepositoryOpaqueTokenIntrospector) {
                Field delegate =
                        getDeclaredFieldByType(UserRepositoryOpaqueTokenIntrospector.class, OpaqueTokenIntrospector.class);
                if (delegate == null) {
                    delegate = getDeclaredFieldByType(UserRepositoryOpaqueTokenIntrospector.class, NimbusOpaqueTokenIntrospector.class);
                }
                if (delegate != null) {
                    delegate.setAccessible(true);
                    nimbus = (NimbusOpaqueTokenIntrospector) delegate.get(introspector);
                }
            }

            if (nimbus != null) {
                nimbus.setRequestEntityConverter(
                        defaultRequestEntityConverter(URI.create(this.authz.introspectionUri())));
            }
        }

        private Converter<String, RequestEntity<?>> defaultRequestEntityConverter(URI introspectionUri) {
            return token -> {
                HttpHeaders headers = requestHeaders();
                MultiValueMap<String, String> body = requestBody(token);
                return new RequestEntity<>(body, headers, HttpMethod.POST, introspectionUri);
            };
        }

        private HttpHeaders requestHeaders() {
            HttpHeaders headers = new HttpHeaders();
            headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON_UTF8));
            return headers;
        }

        private MultiValueMap<String, String> requestBody(String token) {
            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("token", token);
            return body;
        }
    }

    @Test
    public void task_1() {
        // add application.yml configuration
        assertTrue("Task 1: Could not find a bean in the application context that will verify the bearer token. " +
                "Make sure that you are specifying the correct property in `application.yml`", this.jwt != null || this.introspector != null);

        if (this.introspector != null) {
            String introspectionUrl = "http://localhost:9999/auth/realms/one/protocol/openid-connect/token/introspect";
            assertEquals(
                    "Task 1: Make sure that the `introspection-uri` property is set to `" + introspectionUrl + "`",
                    introspectionUrl, this.introspectionUrl);
        } else {
            String issuerUri = "http://localhost:9999/auth/realms/one";
            assertEquals(
                    "Task 1: Make sure that the `issuer-uri` property is set to `" + issuerUri + "`",
                    issuerUri, this.issuerUri);
        }
    }

    @Test
    public void task_2() throws Exception {
        task_1();
        // add oauth2ResourceServer DSL call

        String token = this.authz.token("user", "resolution:read");
        MvcResult result = this.mvc.perform(get("/resolutions")
                .header("Authorization", "Bearer " + token))
                .andReturn();
        assertNotEquals(
                "Task 2: Make sure that you've configured the application to use Bearer token authentication by adding the appropriate " +
                        "oauth2ResourceServer call to the Spring Security DSL in `ResolutionsApplication`",
                401, result.getResponse().getStatus());
        // until we add scopes, this will be a 403; after we add scopes, it'll be a 200. But it will never been a 401.

        this.authz.revoke(token);
    }

    @Test
    public void task_3() throws Exception {
        task_2();
        // Add JwtAuthenticationConverter

        assertNotNull(
                "Task 3: Make sure to publish an instance of `JwtAuthenticationConverter` as a `@Bean`",
                this.jwtAuthenticationConverter);

        String token = this.authz.token("user", "resolution:read");
        Authentication authentication = getAuthentication(token);
        assertFalse(
                "Task 3: For a token with a scope of `resolution:read`, `JwtAuthenticationConverter` returned no scopes back",
                authentication.getAuthorities().isEmpty());
        assertEquals(
                "Task 3: For a token with a scope of `resolution:read`, a `GrantedAuthority` of `resolution:read` was not returned. " +
                        "Make sure that you are setting the authority prefix in `JwtGrantedAuthoritiesConverter`",
                "resolution:read", authentication.getAuthorities().iterator().next().getAuthority());
    }

    @Test
    public void task_4() throws Exception {
        task_3();

        Field nameField = getDeclaredFieldByColumnName(User.class, "full_name");
        assertNotNull(
                "Please add a full name property to the `User` class with a column called `full_name`",
                nameField);

        ReflectedUser user = new ReflectedUser((User) this.userDetailsService.loadUserByUsername("hasread"));
        ReflectedUser copy = ReflectedUser.copiedInstance(user);
        assertEquals(
                "Task 4: Update your copy constructor so that the full name is also copied",
                user.getFullName(), copy.getFullName());

        assertTrue(
                "Task 4: Please give each user a name by calling `setFullName` in `ResolutionInitializer`.",
                StringUtils.hasText(user.getFullName()));

        this.resolutionRepository.save(new Resolution("new read resolution", "hasread"));

        String token = this.authz.token("hasread", "resolution:read", "user:read");
        Authentication authentication = getAuthentication(token);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        try {
            Iterable<Resolution> resolutions = this.resolutionController.read();
            for (Resolution resolution : resolutions) {
                assertTrue(
                        "Task 4: Please update the `/resolutions` endpoint to query the `UserRepository` for the user's personal name. " +
                                "Then, append that to the end of the `text` value in each `Resolution` returned",
                        resolution.getText().endsWith(user.getFullName()));
            }
        } finally {
            SecurityContextHolder.clearContext();
            this.authz.revoke(token);
        }
    }

    @Test
    public void task_5() throws Exception {
        task_4();
        // conditionally send user's name in result, based on permission

        ReflectedUser user = new ReflectedUser((User) this.userDetailsService.loadUserByUsername("hasread"));
        String token = this.authz.token("hasread", "resolution:read");
        Authentication authentication = getAuthentication(token);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        try {
            Iterable<Resolution> resolutions = this.resolutionController.read();
            for (Resolution resolution : resolutions) {
                assertFalse(
                        "Task 5: The `/resolution` endpoint appended the user's personal name, even though that permission " +
                                "was not granted to the client.",
                        resolution.getText().endsWith(user.getFullName()));
            }
        } finally {
            SecurityContextHolder.clearContext();
            this.authz.revoke(token);
        }
    }

    @Test
    public void task_6() throws Exception {
        task_5();

        // reconcile with UserRepository using JwtAuthenticationConverter

        assertNotNull(
                "Task 6: Please make sure that you've supplied an instance of `UserRepositoryJwtAuthenticationConverter` to the Spring Security DSL",
                this.jwtAuthenticationConverter instanceof UserRepositoryJwtAuthenticationConverter);

        String token = this.authz.token(UUID.randomUUID().toString(), "resolution:write");
        try {
            getAuthentication(token);
            fail(
                    "Task 6: Create a custom `Converter<Jwt, AbstractAuthenticationToken>` that reconciles the `sub` field in the `Jwt` " +
                            "with what's in the `UserRepository`. If the user isn't there, throw a `UsernameNotFoundException`. " +
                            "Also, make sure that you've removed the `JwtAuthenticationConverter` `@Bean` definition since this custom one you are writing replaces that.");
        } catch (UsernameNotFoundException expected) {
            // ignore
        }
    }

    @Test
    public void task_7() throws Exception {
        task_6();
        // custom authentication token

        String token = this.authz.token("hasread", "resolution:read");
        Authentication authentication = getAuthentication(token);
        assertTrue(
                "Task 7: Make sure that you've correctly mapped a `User` to an `OAuth2AuthenticatedPrincipal`.",
                authentication instanceof BearerTokenAuthentication);
        this.authz.revoke(token);
    }

    @Test
    public void task_8() throws Exception {
        task_7();
        // merge scopes and roles

        String mismatch = this.authz.token("hasread", "resolution:write"); // client grants, but user doesn't have
        MvcResult result = this.mvc.perform(post("/resolution")
                .content("my resolution")
                .header("Authorization", "Bearer " + mismatch))
                .andReturn();
        assertEquals(
                "Task 8: Client successfully wrote a resolution for `hasread`, even though `hasread` doesn't have that authority. " +
                        "Make sure that the scopes in the `Jwt` are only granted if the user actually has that authority",
                403, result.getResponse().getStatus());
        this.authz.revoke(mismatch);
        String missing = this.authz.token("hasread"); // client doesn't grant
        result = this.mvc.perform(get("/resolutions")
                .header("Authorization", "Bearer " + missing))
                .andReturn();
        assertEquals(
                "Task 7: Client successfully read a resolution for `hasread`, even though `hasread` didn't grant it that permission. " +
                        "Make sure that the scopes in the `Jwt` are only granted if the user grants that authority to the client.",
                403, result.getResponse().getStatus());
        this.authz.revoke(missing);
    }

    private Authentication getAuthentication(String token) {
        if (this.jwt != null) {
            Jwt jwt = this.jwt.decode(token);
            return this.jwtAuthenticationConverter.convert(jwt);
        }

        OAuth2AuthenticatedPrincipal principal = this.introspector.introspect(token);
        OAuth2AccessToken credentials = new OAuth2AccessToken(BEARER, token, null, null);
        return new BearerTokenAuthentication(principal, credentials, principal.getAuthorities());
    }
}
