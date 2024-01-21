package org.learning.java.service;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.ObjectUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.Arrays;
import java.util.Collections;

@Slf4j
@Service
public class BaggageUserDetailService implements UserDetailsService {
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
        HttpSession session = request.getSession();
        String clientId = ObjectUtils.toString(session.getAttribute("client_id"));
        String scope = ObjectUtils.toString(session.getAttribute("scope"));
        String password = request.getParameter("password");

        request.getParameterMap().forEach((key, value) ->{
            log.info("BaggageUserDetailService -> key: {} value: {}", key, Arrays.toString(value));
        });
        log.info("{}", password);
        log.info("BaggageUserDetailService -> loadUserByUsername {}", request.getQueryString());
        UserDetails userDetails = User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .roles("USER")
                .build();
        return userDetails;
    }
}
