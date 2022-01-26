package com.com.investment.websecuritylibrary.filter;

import com.com.investment.websecuritylibrary.exception.InvalidAuthorizationHeaderException;
import com.com.investment.websecuritylibrary.jwt.JwtUtility;
import com.com.investment.websecuritylibrary.service.CustomUserDetailService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;
import java.util.function.BiPredicate;
import java.util.function.Function;

@Component
@Slf4j
public class JwtRequestFilter extends OncePerRequestFilter {

    private CustomUserDetailService userDetailService;
    private JwtUtility jwtUtility;

    @Autowired
    public JwtRequestFilter(CustomUserDetailService userDetailService, JwtUtility jwtUtility) {
        this.userDetailService = userDetailService;
        this.jwtUtility = jwtUtility;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        final Optional<String> authorizationHeader = Optional.of(request.getHeader("Authorization"))
                .filter(s -> s.startsWith("Bearer "));
        final Optional<JwtToken> jwtToken = buildJwt.apply(authorizationHeader);
        final JwtToken token = jwtToken.get(); // what happens when .get() is called on empty Optional (No value set/found)

        if (userDetailsParams.test(token.getUsername(), SecurityContextHolder.getContext().getAuthentication())) {
            UserDetails userDetails = userDetailService.loadUserByUsername(token.getUsername());

            if (jwtUtility.validateToken(token.getToken(), userDetails)) {
                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());
                usernamePasswordAuthenticationToken
                        .setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
            }
        } else {
            return;
        }
        filterChain.doFilter(request, response);
    }

    Function<Optional<String>, Optional<JwtToken>> buildJwt = authHeader -> {
        String token = authHeader.orElseThrow(InvalidAuthorizationHeaderException::new).substring(7);
        return authHeader.isPresent() ?
                Optional.of(JwtToken.builder()
                        .token(token)
                        .username(jwtUtility.extractUsername(token))
                        .build())
                : Optional.empty();
    };

    BiPredicate<String, Authentication> userDetailsParams = (username, authentication) -> username != null && authentication == null;
}