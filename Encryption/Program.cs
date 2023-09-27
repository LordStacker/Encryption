using System.Security.Cryptography;
using System.Text;

class EncryptionProgram
{
    static void Main()
    {
        bool breakFlag = true;

        while (breakFlag)
        {
            Console.WriteLine("Select an option:");
            Console.WriteLine("1. Encrypt and save a message to a file");
            Console.WriteLine("2. Read and decrypt a message from a file");
            Console.WriteLine("3. Exit");

            string option = Console.ReadLine();

            switch (option)
            {
                case "1":
                    EncryptAndSaveMessage();
                    break;
                case "2":
                    ReadAndDecryptFromFile();
                    break;
                case "3":
                    breakFlag = false;
                    break;
                default:
                    Console.WriteLine("Invalid option. Please choose 1, 2, or 3.");
                    break;
            }
        }
    }

    static void EncryptAndSaveMessage()
    {
        Console.Write("Enter the encryption key (16 characters): ");
        string encryptionKey = Console.ReadLine();

        if (encryptionKey.Length != 16)
        {
            Console.WriteLine("Encryption key must be exactly 16 characters long.");
            return;
        }

        Console.Write("Enter the message to encrypt: ");
        string message = Console.ReadLine();
        Console.Write("Enter the output file name: ");
        string outputFile = Console.ReadLine();

        byte[] key = Encoding.UTF8.GetBytes(encryptionKey);
        byte[] nonce = new byte[12];

        using (AesGcm aesGcm = new AesGcm(key))
        {
            byte[] encryptedMessage = new byte[message.Length];
            byte[] authenticationTag = new byte[16];

            aesGcm.Encrypt(nonce, Encoding.UTF8.GetBytes(message), encryptedMessage, authenticationTag);

            using (FileStream fileStream = File.Create(outputFile))
            {
                fileStream.Write(nonce);
                fileStream.Write(authenticationTag);
                fileStream.Write(encryptedMessage);
            }
        }

        Console.WriteLine("Message encrypted and saved to file: " + outputFile);
    }

    static void ReadAndDecryptFromFile()
    {
        Console.Write("Enter the decryption key (16 characters): ");
        string decryptionKey = Console.ReadLine();

        if (decryptionKey.Length != 16)
        {
            Console.WriteLine("Decryption key must be exactly 16 characters long.");
            return;
        }

        Console.Write("Enter the input file name: ");
        string inputFile = Console.ReadLine();

        byte[] key = Encoding.UTF8.GetBytes(decryptionKey);
        byte[] receivedNonce = new byte[12];

        try
        {
            using (AesGcm aesGcm = new AesGcm(key))
            using (FileStream fileStream = File.OpenRead(inputFile))
            {
                byte[] receivedAuthenticationTag = new byte[16];
                byte[] encryptedMessage = new byte[fileStream.Length - 28]; 

                fileStream.Read(receivedNonce, 0, 12);
                fileStream.Read(receivedAuthenticationTag, 0, 16);
                fileStream.Read(encryptedMessage, 0, encryptedMessage.Length);

                byte[] decryptedMessage = new byte[encryptedMessage.Length];
                aesGcm.Decrypt(receivedNonce, encryptedMessage, receivedAuthenticationTag, decryptedMessage);

                string decryptedText = Encoding.UTF8.GetString(decryptedMessage);
                Console.WriteLine("Decrypted Message:");
                Console.WriteLine(decryptedText);
            }
        }
        catch (FileNotFoundException)
        {
            Console.WriteLine("File not found.");
        }
        catch (Exception)
        {
            Console.WriteLine("Decryption failed. Incorrect decryption key or corrupted file.");
        }
    }
}
