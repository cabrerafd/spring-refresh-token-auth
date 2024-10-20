package com.cabrerafd.security.exception;

import com.cabrerafd.security.response.ErrorResponse;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

@ControllerAdvice
public class Handler {

    @ExceptionHandler(value = InvalidRefreshToken.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public @ResponseBody ErrorResponse handleInvalidRefreshToken(InvalidRefreshToken e) {
        return new ErrorResponse(HttpStatus.FORBIDDEN.value(), e.getMessage());
    }
}
