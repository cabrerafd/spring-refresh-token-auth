package com.cabrerafd.security.helpers.annotations;

import com.cabrerafd.security.helpers.IdGenerator;
import org.hibernate.annotations.IdGeneratorType;
import org.hibernate.annotations.ValueGenerationType;

import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import static java.lang.annotation.ElementType.FIELD;
import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

@IdGeneratorType(IdGenerator.class)
@ValueGenerationType(generatedBy = IdGenerator.class)
@Retention(RUNTIME)
@Target({ FIELD, METHOD })
public @interface CustomIdGenerator {

    String prefix() default "id";

}
