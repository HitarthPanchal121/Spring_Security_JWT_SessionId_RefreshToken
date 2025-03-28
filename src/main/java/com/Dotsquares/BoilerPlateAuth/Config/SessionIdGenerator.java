package com.Dotsquares.BoilerPlateAuth.Config;

import com.Dotsquares.BoilerPlateAuth.Entity.User;

import java.util.Random;

public class SessionIdGenerator {
    private static final Random random = new Random();

    /**
     * Generates a session ID in the format:
     * [FirstName(3)]-[Random1(3)]-[Checksum(3)]-[Random2(3)]-[IPLast(3)]
     *
     * @param user The user entity containing at least firstName and email.
     * @param ipAddress The IP address of the user (e.g. "192.168.0.123").
     * @return A custom session ID string.
     */
    public static String generateSessionId(User user, String ipAddress) {
        // Get first three letters of firstName (padded if needed)
        String firstName = user.getFirstName();
        String firstNamePart = firstName.length() >= 3
                ? firstName.substring(0, 3)
                : String.format("%-3s", firstName).replace(' ', 'X'); // pad with X if less than 3

        // Generate two random numbers (1 to 100) and format as three-digit numbers
        String random1 = String.format("%03d", random.nextInt(100) + 1);
        String random2 = String.format("%03d", random.nextInt(100) + 1);

        // Compute checksum based on user's email (simple sum of char codes mod 1000)
        int checksumVal = 0;
        for (char ch : user.getEmail().toCharArray()) {
            checksumVal += ch;
        }
        checksumVal %= 1000;
        String checksum = String.format("%03d", checksumVal);

        // Extract the last segment of the IP address and format as a three-digit number.
        String[] ipParts = ipAddress.split("\\.");
        String ipLastPart = ipParts[ipParts.length - 1];
        int ipLast = Integer.parseInt(ipLastPart);
        String ipLastFormatted = String.format("%03d", ipLast);

        String sessionId = String.join("-", firstNamePart.toUpperCase(), random1, checksum, random2, ipLastFormatted);

        System.out.println("Generated Session ID: " + sessionId);

        return sessionId;
    }
}