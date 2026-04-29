import java.io.*;
import java.security.*;
import java.util.*;

/**
 * Manages accounts across three password files:
 *   passwords1.txt - plaintext username:password
 *   passwords2.txt - username:SHA-256(password)
 *   passwords3.txt - username:salt:SHA-256(password+salt)
 * Environment: IntelliJ IDEA
 */
public class PasswordManager {

    static final String FILE1 = "passwords1.txt";
    static final String FILE2 = "passwords2.txt";
    static final String FILE3 = "passwords3.txt";

    public static void main(String[] args) throws Exception {
        Scanner sc = new Scanner(System.in);

        System.out.print("Max password length (digits only): ");
        int maxLen = Integer.parseInt(sc.nextLine().trim());

        System.out.print("(1) Create account  (2) Authenticate: ");
        String choice = sc.nextLine().trim();

        System.out.print("Username (exactly 10 alphabetic characters): ");
        String username = sc.nextLine().trim();
        if (!username.matches("[a-zA-Z]{10}")) {
            System.out.println("Invalid username. Must be exactly 10 alphabetic characters.");
            return;
        }

        System.out.print("Password (digits [0-9] only, max " + maxLen + " digits): ");
        String password = sc.nextLine().trim();
        if (!password.matches("[0-9]{1," + maxLen + "}")) {
            System.out.println("Invalid password. Must be 1-" + maxLen + " digits [0-9].");
            return;
        }

        switch (choice) {
            case "1" -> createAccount(username, password);
            case "2" -> authenticate(username, password);
            default  -> System.out.println("Invalid option.");
        }
    }


    // Account creation
    static void createAccount(String username, String password) throws Exception {
        // File 1: plaintext
        appendLine(FILE1, username + ":" + password);

        // File 2: username:SHA-256(password)
        appendLine(FILE2, username + ":" + sha256(password));

        // File 3: username:salt(hex):SHA-256(password+salt)
        byte[] saltBytes = new byte[1];
        new SecureRandom().nextBytes(saltBytes);
        String salt = bytesToHex(saltBytes);
        appendLine(FILE3, username + ":" + salt + ":" + sha256(password + salt));

        System.out.println("Account created successfully.");
    }


    // Authentication
    static void authenticate(String username, String password) throws Exception {
        System.out.println("File 1 (plaintext):    " + (checkFile1(username, password) ? "SUCCESS" : "FAILED"));
        System.out.println("File 2 (hashed):       " + (checkFile2(username, password) ? "SUCCESS" : "FAILED"));
        System.out.println("File 3 (salted hash):  " + (checkFile3(username, password) ? "SUCCESS" : "FAILED"));
    }

    static boolean checkFile1(String username, String password) throws IOException {
        for (String line : readLines(FILE1)) {
            String[] p = line.split(":", 2);
            if (p.length == 2 && p[0].equals(username) && p[1].equals(password)) return true;
        }
        return false;
    }

    static boolean checkFile2(String username, String password) throws Exception {
        String hash = sha256(password);
        for (String line : readLines(FILE2)) {
            String[] p = line.split(":", 2);
            if (p.length == 2 && p[0].equals(username) && p[1].equals(hash)) return true;
        }
        return false;
    }

    static boolean checkFile3(String username, String password) throws Exception {
        for (String line : readLines(FILE3)) {
            String[] p = line.split(":", 3);
            if (p.length == 3 && p[0].equals(username)) {
                if (p[2].equals(sha256(password + p[1]))) return true;
            }
        }
        return false;
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
        File f = new File(filename);
        if (!f.exists()) return lines;
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            String line;
            while ((line = br.readLine()) != null) {
                if (!line.isBlank()) lines.add(line);
            }
        }
        return lines;
    }

    static void appendLine(String filename, String line) throws IOException {
        try (PrintWriter pw = new PrintWriter(new FileWriter(filename, true))) {
            pw.println(line);
        }
    }
}
