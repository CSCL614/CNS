import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class BlowfishAlgorithm {
    public static void main(String[] args) {
        try {
            // Generate a 32-bit (4-byte) key for Blowfish
            KeyGenerator keyGenerator = KeyGenerator.getInstance("Blowfish");
            keyGenerator.init(32); // 32-bit key
            SecretKey secretKey = keyGenerator.generateKey();
            byte[] keyBytes = secretKey.getEncoded();
            SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "Blowfish");

            // Generate an Initialization Vector (IV)
            SecureRandom random = new SecureRandom();
            byte[] iv = new byte[8]; // Blowfish uses a block size of 8 bytes
            random.nextBytes(iv);
            System.out.println("Initialization Vector: " + Base64.getEncoder().encodeToString(iv));

            // Specify input and output file names
            File inputFile = new File("input.txt");
            File encryptedFile = new File("encrypted.txt");

            if (!inputFile.exists()) {
                System.out.println("The file not found. Ensure input file .txt exists.");
                return;
            }

            // Perform encryption
            encryptFile(keySpec, inputFile, encryptedFile);
            System.out.println("File encrypted successfully.");
        } catch (Exception e) {
            System.out.println("An error occurred during encryption.");
            e.printStackTrace();
        }
    }

    public static void encryptFile(SecretKeySpec keySpec, File inputFile, File outputFile) throws Exception {
        Cipher cipher = Cipher.getInstance("Blowfish");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);

        FileInputStream inputStream = new FileInputStream(inputFile);
        byte[] inputBytes = new byte[(int) inputFile.length()];
        inputStream.read(inputBytes);
        byte[] outputBytes = cipher.doFinal(inputBytes);

        FileOutputStream outputStream = new FileOutputStream(outputFile);
        outputStream.write(outputBytes);

        inputStream.close();
        outputStream.close();
    }
}
