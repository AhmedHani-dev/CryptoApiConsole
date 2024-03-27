using CryptoAPIConsole;

string password = "Super Secret Key";
byte[] key = CryptoBackend.deriveKey(password);

Console.WriteLine("Enter Text To Encrypt");
string? plainTextToEncrypt = Console.ReadLine();

string encryptedText = CryptoBackend.encrypt(key, plainTextToEncrypt);
Console.WriteLine("Encrypted Text: " + encryptedText);

string decryptedText = CryptoBackend.decrypt(key, encryptedText);
Console.WriteLine("Decrypted Text: " + decryptedText);