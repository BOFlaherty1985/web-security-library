package com.com.investment.websecuritylibrary.filter;

import com.com.investment.websecuritylibrary.exception.InvalidAuthorizationHeaderException;
import com.com.investment.websecuritylibrary.jwt.JwtUtility;
import com.com.investment.websecuritylibrary.service.CustomUserDetailService;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.security.core.userdetails.UserDetails;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class JwtRequestFilterTest {

    @InjectMocks
    private JwtRequestFilter jwtRequestFilter;

    @Mock
    private CustomUserDetailService userDetailService;

    @Mock
    private JwtUtility jwtUtility;

    private final String JWT_TOKEN
            = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0VXNlciIsImV4cCI6MTY0MjgxNTQ0NH0.aKhDT8qlmWGxJDwEbURqUIzquUTWqzhcvFVfQlfPY88";

    private final String INVALID_JWT_TOKEN
            = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0VXNlciIsImV4cCI6MTY0MjgxNTQ0NH0.aKhDT8qlmWGxJDwEbURqUIzquUTWqzhcvFVfQlfPY88";

    @Test
    public void shouldThrowErrorIfAuthorizationTokenIsNotFormattedCorrectly() throws ServletException, IOException {
        // given
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeader("Authorization")).thenReturn(INVALID_JWT_TOKEN);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain filterChain = mock(FilterChain.class);

        // when
        Assertions.assertThrows(InvalidAuthorizationHeaderException.class, () -> jwtRequestFilter.doFilterInternal(request, response, filterChain));
    }

    @Test
    public void shouldExtractJwtFromHeaderAndValidate() throws ServletException, IOException {
        // given
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeader("Authorization")).thenReturn(JWT_TOKEN);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain filterChain = mock(FilterChain.class);

        String extractedJwtToken = JWT_TOKEN.substring(7);
        String username = "testUser";
        when(jwtUtility.extractUsername(extractedJwtToken)).thenReturn(username);

        UserDetails userDetails = mock(UserDetails.class);
        when(userDetails.getUsername()).thenReturn(username);
        when(userDetails.getPassword()).thenReturn("password");

        doReturn(userDetails).when(userDetailService).loadUserByUsername(username);

        // when
        jwtRequestFilter.doFilterInternal(request, response, filterChain);

        // then
        verify(jwtUtility).extractUsername(extractedJwtToken);
        verify(userDetailService).loadUserByUsername(username);
        verify(jwtUtility).validateToken(extractedJwtToken, userDetails);
    }
}