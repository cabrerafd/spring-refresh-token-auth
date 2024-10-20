package com.cabrerafd.security.helpers;

import com.cabrerafd.security.helpers.annotations.CustomIdGenerator;
import org.hibernate.engine.spi.SharedSessionContractImplementor;
import org.hibernate.generator.BeforeExecutionGenerator;
import org.hibernate.generator.EventType;
import org.hibernate.generator.GeneratorCreationContext;
import org.hibernate.id.factory.spi.CustomIdGeneratorCreationContext;

import java.lang.reflect.Member;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.EnumSet;

import static org.hibernate.generator.EventTypeSets.INSERT_ONLY;

public class IdGenerator implements BeforeExecutionGenerator {

    private final String prefix;

    private final static String alphanumeric = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

    private final static SecureRandom secureRandom;

    static {
        try {
            secureRandom = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private IdGenerator(CustomIdGenerator config) {
        this.prefix = config.prefix();
    }

    @SuppressWarnings("unused")
    public IdGenerator(
            CustomIdGenerator config,
            Member idMember,
            CustomIdGeneratorCreationContext creationContext) {
        this(config);
    }

    @SuppressWarnings("unused")
    public IdGenerator(
            CustomIdGenerator config,
            Member member,
            GeneratorCreationContext creationContext) {
        this(config);
    }

    @Override
    public EnumSet<EventType> getEventTypes() {
        return INSERT_ONLY;
    }

    @Override
    public Object generate(SharedSessionContractImplementor session, Object owner, Object currentValue,
                           EventType eventType) {
        return generateRandomId(prefix);
    }

    public static String generateRandomId(String prefix) {
        return prefix + "_" + secureRandom
                .ints(24, 0, alphanumeric.length())
                .mapToObj(alphanumeric::charAt)
                .collect(StringBuilder::new, StringBuilder::append, StringBuilder::append);
    }
}
