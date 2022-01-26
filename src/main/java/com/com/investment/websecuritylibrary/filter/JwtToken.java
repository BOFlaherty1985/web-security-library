package com.com.investment.websecuritylibrary.filter;

import lombok.Builder;
import lombok.Data;
import lombok.ToString;

@Data
@Builder
@ToString
public class JwtToken {

    private String username;
    private String token;
}
