package com.com.investment.websecuritylibrary.web.model;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
@EqualsAndHashCode
public class AuthenticationResponse {

    private String jwtToken;

}
