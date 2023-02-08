package com.metoo.nspm.core.ssh.utils;

import java.security.SecureRandom;
import java.util.UUID;

public class IdGenerator {
    private static SecureRandom random = new SecureRandom();

    public IdGenerator() {
    }

    public static String uuid() {
        return UUID.randomUUID().toString().replaceAll("-", "");
    }

    public static long randomLong() {
        return Math.abs(random.nextLong());
    }

    public static String randomBase62(int length) {
        byte[] randomBytes = new byte[length];
        random.nextBytes(randomBytes);
        return Encodes.encodeBase62(randomBytes);
    }

    public static void main(String[] args) {
        System.out.println(uuid());
        System.out.println(uuid().length());

        for(int i = 0; i < 1000; ++i) {
            System.out.println(randomLong() + "  " + randomBase62(5));
        }

    }
}
