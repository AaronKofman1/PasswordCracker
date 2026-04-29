import java.io.*;
import java.security.*;
import java.util.*;

/**
 * CS3780 Project 2 - Task 2: Password Cracker
 * Aaron Kofman and Tyler Skinner
 * Brute-forces digit-only passwords of exactly the specified length
 * against type 2 or type 3 password files.
 * Environment: IntelliJ IDEA
 */
public class PasswordCracker {

    public static void main(String[] args) throws Exception {
        Scanner sc = new Scanner(System.in);

        System.out.print("Password file type (2 or 3): ");
        int type = Integer.parseInt(sc.nextLine().trim());
        if (type != 2 && type != 3) {
            System.out.println("Invalid type. Must be 2 or 3.");
            return;
        }

        System.out.print("Max password length: ");
        int maxLen = Integer.parseInt(sc.nextLine().trim());

        String filename = "passwords" + type + ".txt";
        if (!new File(filename).exists()) {
            System.out.println("File not found: " + filename);
            return;
        }

        System.out.println("Cracking " + filename + " with length " + maxLen + "...");
        long start = System.currentTimeMillis();

        List<String> results = (type == 2) ? crackType2(filename, maxLen) : crackType3(filename, maxLen);

        long elapsed = System.currentTimeMillis() - start;
        if (results.isEmpty()) {
            System.out.println("No passwords of length " + maxLen + " found.");
        } else {
            System.out.println("Cracked " + results.size() + " account(s):");
            for (String r : results) System.out.println("  " + r);
        }
        System.out.println("Time elapsed: " + elapsed + " ms");
    }


    // Type 2: check only candidates of exactly maxLen digits
    static List<String> crackType2(String filename, int maxLen) throws Exception {
        Map<String, String> hashToUser = new HashMap<>();
        for (String line : readLines(filename)) {
            String[] p = line.split(":", 2);
            if (p.length == 2) hashToUser.put(p[1], p[0]);
        }

        List<String> cracked = new ArrayList<>();
        long total = (long) Math.pow(10, maxLen);
        for (long i = 0; i < total; i++) {
            String candidate = String.format("%0" + maxLen + "d", i);
            String hash = sha256(candidate);
            if (hashToUser.containsKey(hash)) {
                cracked.add(hashToUser.get(hash) + ":" + candidate);
                hashToUser.remove(hash);
            }
            if (hashToUser.isEmpty()) break;
        }
        return cracked;
    }


    // Type 3: check only candidates of exactly maxLen digits
    static List<String> crackType3(String filename, int maxLen) throws Exception {
        List<String[]> entries = new ArrayList<>();
        for (String line : readLines(filename)) {
            String[] p = line.split(":", 3);
            if (p.length == 3) entries.add(p); // [username, salt, saltedHash]
        }

        List<String> cracked = new ArrayList<>();
        Set<String> crackedUsers = new HashSet<>();

        long total = (long) Math.pow(10, maxLen);
        for (long i = 0; i < total; i++) {
            String candidate = String.format("%0" + maxLen + "d", i);
            for (String[] entry : entries) {
                if (crackedUsers.contains(entry[0])) continue;
                if (sha256(candidate + entry[1]).equals(entry[2])) {
                    cracked.add(entry[0] + ":" + candidate);
                    crackedUsers.add(entry[0]);
                }
            }
            if (crackedUsers.size() == entries.size()) break;
        }
        return cracked;
    }


    // Utilities
    static String sha256(String input) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return bytesToHex(md.digest(input.getBytes()));
    }

    static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    static List<String> readLines(String filename) throws IOException {
        List<String> lines = new ArrayList<>();
        try (BufferedReader br = new BufferedReader(new FileReader(filename))) {
            String line;
            while ((line = br.readLine()) != null) {
                if (!line.isBlank()) lines.add(line);
            }
        }
        return lines;
    }
}