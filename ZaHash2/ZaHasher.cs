using System.Security.Cryptography;
using System.Text;

namespace ZaHash2
{
    public class ZaHasher
    {
        /// <summary>
        /// Computes the hash of the input data by applying SHA-256 and an XOR transformation with a salt.
        /// </summary>
        /// <param name="data">Byte array to be hashed.</param>
        /// <returns>A hexadecimal string containing the salt and the modified hash.</returns>
        public static string HashData(byte[] data)
        {
            // 1. Compute the SHA-256 hash of the data
            byte[] shaHash;

            using (SHA256 sha256 = SHA256.Create())
            {
                shaHash = sha256.ComputeHash(data);
            }

            // 2. Securely generate 2 random bytes (salt)
            byte[] salt = new byte[2];

            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }

            // 3. Apply an alternating XOR operation between each byte of the hash and the salt
            byte[] modifiedHash = new byte[shaHash.Length];

            for (int i = 0; i < shaHash.Length; i++)
            {
                // Use salt[0] for even indices, salt[1] for odd ones
                byte key = (i % 2 == 0) ? salt[0] : salt[1];
                modifiedHash[i] = (byte)(shaHash[i] ^ key);
            }

            // 4. Construct the final string: salt (2 bytes, 4 hexadecimal characters) + modified hash
            StringBuilder sb = new StringBuilder();

            sb.Append(salt[0].ToString("X2"));
            sb.Append(salt[1].ToString("X2"));

            foreach (byte b in modifiedHash)
            {
                sb.Append(b.ToString("X2"));
            }

            return sb.ToString();
        }

        /// <summary>
        /// Checks if the provided hash matches the input data.
        /// </summary>
        /// <param name="hash">Hexadecimal hash to be verified.</param>
        /// <param name="data">Byte array of the original data.</param>
        /// <returns>True if the hash matches, false otherwise.</returns>
        public static bool IsHashValid(string hash, byte[] data)
        {
            if (string.IsNullOrEmpty(hash) || hash.Length != 4 + 64)
            {
                return false;
            }

            // 1. Extract the salt (first 4 characters)
            byte salt0 = byte.Parse(hash.Substring(0, 2), System.Globalization.NumberStyles.HexNumber);
            byte salt1 = byte.Parse(hash.Substring(2, 2), System.Globalization.NumberStyles.HexNumber);
            byte[] salt = new byte[] { salt0, salt1 };

            // 2. Extract the modified hash
            string modifiedHashHex = hash.Substring(4);
            byte[] modifiedHash = new byte[modifiedHashHex.Length / 2];

            for (int i = 0; i < modifiedHash.Length; i++)
            {
                modifiedHash[i] = byte.Parse(modifiedHashHex.Substring(i * 2, 2), System.Globalization.NumberStyles.HexNumber);
            }

            // 3. Reverse the XOR operation to retrieve the original SHA-256 hash
            byte[] originalHash = new byte[modifiedHash.Length];

            for (int i = 0; i < modifiedHash.Length; i++)
            {
                byte key = (i % 2 == 0) ? salt[0] : salt[1];
                originalHash[i] = (byte)(modifiedHash[i] ^ key);
            }

            // 4. Compute the SHA-256 hash of the input data
            byte[] expectedHash;

            using (SHA256 sha256 = SHA256.Create())
            {
                expectedHash = sha256.ComputeHash(data);
            }

            // 5. Manual secure comparison to prevent timing attacks
            if (originalHash.Length != expectedHash.Length)
            {
                return false;
            }

            bool isEqual = true;

            for (int i = 0; i < originalHash.Length; i++)
            {
                if (originalHash[i] != expectedHash[i])
                {
                    isEqual = false; // Do not break the loop to avoid timing attacks
                }
            }

            return isEqual;
        }
    }
}