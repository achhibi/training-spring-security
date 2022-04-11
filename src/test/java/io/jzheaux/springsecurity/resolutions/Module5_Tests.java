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
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.server.resource.introspection.NimbusOpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.client.WebClient;

import java.lang.reflect.Field;
import java.net.URI;
import java.util.Collection;
import java.util.Collections;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import static io.jzheaux.springsecurity.resolutions.ReflectionSupport.getDeclaredFieldByColumnName;
import static io.jzheaux.springsecurity.resolutions.ReflectionSupport.getDeclaredFieldByName;
import static io.jzheaux.springsecurity.resolutions.ReflectionSupport.getDeclaredFieldByType;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;

@RunWith(SpringRunner.class)
@AutoConfigureMockMvc(print= MockMvcPrint.NONE)
@SpringBootTest
public class Module5_Tests {

    @Autowired
    MockMvc mvc;


    @Value("${spring.security.oauth2.resourceserver.opaquetoken.introspection-uri:#{null}}")
    String introspectionUrl;

    @Autowired(required = false)
    OpaqueTokenIntrospector introspector;


    @Autowired(required = false)
    UserDetailsService userDetailsService;

    @Autowired
    ResolutionController resolutionController;

    @Autowired
    ResolutionRepository resolutionRepository;

    @Autowired
    AuthorizationServer authz;

    @Before
    public void setup() {
        assertNotNull(
                "Module 1: Could not find `UserDetailsService` in the application context; make sure to complete the earlier modules " +
                        "before starting this one", this.userDetailsService);
    }

    @TestConfiguration
    static class WebClientPostProcessor implements DisposableBean {
        static String userBaseUrl;

        MockWebServer userEndpoint = new MockWebServer();

        @Override
        public void destroy() throws Exception {
            this.userEndpoint.shutdown();
        }

        @Autowired(required = false)
        void postProcess(WebClient.Builder web) throws Exception {
            Field field = web.getClass().getDeclaredField("baseUrl");
            field.setAccessible(true);
            userBaseUrl = (String) field.get(web);
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
            return token -> {
                throw new BadJwtException("bad jwt");
            };
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
        assertNotNull(
                "Task 1: Could not find an `OpaqueTokenIntrospector` bean in the application context." +
                "Make sure that you are specifying the correct property in `application.yml`",
                this.introspector);

        String introspectionUrl = "http://localhost:9999/auth/realms/one/protocol/openid-connect/token/introspect";
        assertEquals(
                "Task 1: Make sure that the `introspection-uri` property is set to `" + introspectionUrl + "`",
                introspectionUrl, this.introspectionUrl);
    }

    @Test
    public void task_2() throws Exception {
        task_1();

        String token = this.authz.token("user", "resolution:read");
        try {
            MvcResult result = this.mvc.perform(get("/resolutions")
                    .header("Authorization", "Bearer " + token))
                    .andReturn();
            assertNotEquals(
                    "Task 2: Make sure that you've configured the application to use Bearer token authentication by adding the appropriate " +
                            "oauth2ResourceServer call to the Spring Security DSL in `ResolutionsApplication`",
                    401, result.getResponse().getStatus());
            // until we add scopes, this will be a 403; after we add scopes, it'll be a 200. But it will never been a 401.
        } finally {
            this.authz.revoke(token);
        }
    }

    @Test
    public void task_3() throws Exception {
        task_2();
        // customize OpaqueTokenIntrospector

        assertNotNull(
                "Task 6: Please make sure that you've supplied an instance of `UserRepositoryOpaqueTokenIntrospector` to the application context",
                this.introspector instanceof UserRepositoryOpaqueTokenIntrospector);

        String token = this.authz.token("user", "resolution:read");
        OAuth2AuthenticatedPrincipal principal = this.introspector.introspect(token);
        assertFalse(
                "Task 3: For a token with a scope of `resolution:read`, your custom `OpaqueTokenIntrospector` returned no scopes back",
                principal.getAuthorities().isEmpty());
        assertEquals(
                "Task 3: For a token with a scope of `resolution:read`, a `GrantedAuthority` of `resolution:read` was not returned. " +
                        "Make sure that you are stripping off the `SCOPE_` prefix in your custom `OpaqueTokenIntrospector`",
                "resolution:read", principal.getAuthorities().iterator().next().getAuthority());
    }

    @Test
    public void task_4() throws Exception {
        task_3();

        // add subscription property
        Field nameField = getDeclaredFieldByColumnName(User.class, "subscription");
        assertNotNull(
                "Please add a subscription property to the `User` class with a column called `subscription`",
                nameField);

        ReflectedUser user = new ReflectedUser((User) this.userDetailsService.loadUserByUsername("haswrite"));
        ReflectedUser copy = ReflectedUser.copiedInstance(user);
        assertEquals(
                "Task 4: Update your copy constructor so that the subscription is also copied",
                user.getSubscription(), copy.getSubscription());

        assertEquals(
                "Task 4: Please give `haswrite` a `premium` subscription.",
                "premium", user.getSubscription());

        // add friends property
        Field friendsField = getDeclaredFieldByName(User.class, "friends");
        assertNotNull(
                "Task 4: Please add a friends property to the `User` class that maps to a `Collection` of other `User`s",
                friendsField);

        user = new ReflectedUser((User) this.userDetailsService.loadUserByUsername("haswrite"));
        copy = ReflectedUser.copiedInstance(user);
        Collection<String> userFriends = user.getFriends().stream()
                .map(u -> new ReflectedUser(u).getUsername())
                .collect(Collectors.toList());
        Collection<String> copyFriends = copy.getFriends().stream()
                .map(u -> new ReflectedUser(u).getUsername())
                .collect(Collectors.toList());
        assertEquals(
                "Task 4: The friends of the original and its copy are different.",
                userFriends,
                copyFriends);

        assertFalse(
                "Task 4: Please add `hasread` to `haswrite`'s list of friends",
                userFriends.isEmpty());
        assertTrue(
                "Task 4: Please add `hasread` to `haswrite`'s list of friends",
                userFriends.contains("hasread"));
    }

    @Test
    public void task_5() throws Exception {
        task_4();
        // add share endpoint

        Resolution resolution = this.resolutionRepository.save(new Resolution("haswrite's latest resolution", "haswrite"));
        User haswrite = (User) this.userDetailsService.loadUserByUsername("haswrite");
        TestingAuthenticationToken token = new TestingAuthenticationToken
                (haswrite, haswrite, AuthorityUtils.createAuthorityList("resolution:write", "resolution:share"));
        MvcResult result = this.mvc.perform(put("/resolution/" + resolution.getId() + "/share")
                .with(authentication(token))
                .with(csrf()))
                .andReturn();

        assertEquals(
                "Task 5: The `PUT /resolution/{id}/share` endpoint failed to authorize a user that is granted the `resolution:share` permission.",
                200, result.getResponse().getStatus());
        User hasread = (User) this.userDetailsService.loadUserByUsername("hasread");
        token = new TestingAuthenticationToken
                (hasread, hasread, AuthorityUtils.createAuthorityList("resolution:read"));
        SecurityContextHolder.getContext().setAuthentication(token);
        try {
            Collection<String> texts = StreamSupport.stream(this.resolutionController.read().spliterator(), false)
                    .map(Resolution::getText).collect(Collectors.toList());
            assertTrue(
                    "Task 5: Even though `haswrite` shared a `Resolution` with `hasread`, `hasread` doesn't have it or its getting filtered out. " +
                            "Make sure that you are sending the correct username to `ResolutionController#make",
                    texts.contains("haswrite's latest resolution"));
        } finally {
            SecurityContextHolder.clearContext();
        }

        resolution = this.resolutionRepository.save(new Resolution("user's latest resolution", "user"));
        token = new TestingAuthenticationToken
                (haswrite, haswrite, AuthorityUtils.createAuthorityList("resolution:write", "resolution:share"));
        result = this.mvc.perform(put("/resolution/" + resolution.getId() + "/share")
                .with(authentication(token))
                .with(csrf()))
                .andReturn();

        assertEquals(
                "Task 5: A user with the `resolution:share` authority was able to share a resolution that wasn't theirs.",
                403, result.getResponse().getStatus());

        token = new TestingAuthenticationToken
                (hasread, hasread, AuthorityUtils.createAuthorityList("resolution:read", "user:read"));
        SecurityContextHolder.getContext().setAuthentication(token);
        try {
            Iterable<Resolution> resolutions = this.resolutionController.read();
            for (Resolution hasReadResolutions : resolutions) {
                assertNotEquals(
                    "Task 5: A user with the `resolution:share` authority was able to share a resolution that wasn't theirs.",
                    "user's latest resolution", hasReadResolutions.getText());
            }
        } finally {
            SecurityContextHolder.clearContext();
        }
    }

    @Test
    public void task_6() throws Exception {
        task_5();
        // reconcile with UserRepository using JwtAuthenticationConverter

        String token = this.authz.token(UUID.randomUUID().toString(), "resolution:write");
        try {
            this.introspector.introspect(token);
            fail(
                    "Task 6: Create a custom `OpaqueTokenIntrospector` that reconciles the `sub` field in the token response " +
                            "with what's in the `UserRepository`. If the user isn't there, throw a `UsernameNotFoundException`.");
        } catch (UsernameNotFoundException expected) {
            // ignore
        } finally {
            this.authz.revoke(token);
        }
    }

    @Test
    public void task_7() throws Exception {
        task_6();
        // derive share permission
        String token = this.authz.token("haswrite", "resolution:write");
        try {
            OAuth2AuthenticatedPrincipal principal = this.introspector.introspect(token);
            assertTrue(
                    "Task 7: Make so that when a token is granted `resolution:write` and the user has a `premium` subscription that the " +
                            "final principal as the `resolution:share` authority",
                    principal.getAuthorities().contains(new SimpleGrantedAuthority("resolution:share")));
        } finally {
            this.authz.revoke(token);
        }
    }

    @Test
    public void task_8() throws Exception {
        task_7();
        // create custom principal
        Resolution resolution = this.resolutionRepository.save(new Resolution("haswrite's new resolution", "haswrite"));
        String token = this.authz.token("haswrite", "resolution:write");
        try {
            MvcResult result = this.mvc.perform(put("/resolution/" + resolution.getId() + "/share")
                    .header("Authorization", "Bearer " + token))
                    .andReturn();

            assertEquals(
                    "Task 5: The `/resolution/{id}/share` endpoint failed to authorize a user that is granted the `resolution:share` permission.",
                    200, result.getResponse().getStatus());
        } finally {
            this.authz.revoke(token);
        }
    }

}
