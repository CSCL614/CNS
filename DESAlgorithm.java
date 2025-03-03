import java.util.Base64;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class DESAlgorithm {
    public static void main(String[] args) {
        try {

            KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
            SecretKey secretKey = keyGenerator.generateKey();

            Cipher cipher = Cipher.getInstance("DES");

            Scanner scanner = new Scanner(System.in);
            System.out.print("Enter the string to encrypt: ");
            String inputText = scanner.nextLine();


            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedBytes = cipher.doFinal(inputText.getBytes());
            String encryptedText = Base64.getEncoder().encodeToString(encryptedBytes);
            System.out.println("Encrypted string: " + encryptedText);

            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
            String decryptedText = new String(decryptedBytes);
            System.out.println("Decrypted string: " + decryptedText);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
