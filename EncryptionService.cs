using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;

namespace EncryptDecrypt
{
    public class EncryptionService
    {
        public string EncryptString(string textToEncrypt)
        {
            var key = Environment.GetEnvironmentVariable(Constants.VAR_Key, EnvironmentVariableTarget.User);
            AesSymmetricEncryption encryption = new AesSymmetricEncryption();
            return encryption.Encrypt(textToEncrypt, key);
        }

        public string DecryptString(string textToDecrypt)
        {
            var key = Environment.GetEnvironmentVariable(Constants.VAR_Key, EnvironmentVariableTarget.User);
            AesSymmetricEncryption encryption = new AesSymmetricEncryption();
            return encryption.Decrypt(textToDecrypt, key);
        }

        public interface IAes
        {
            string Decrypt(string ciphertext, string key);
            string Encrypt(string plainText, string key);
        }

		public class AesSymmetricEncryption : IAes
		{
			private readonly int _saltSize = 32;
			private readonly int _iterationCount = 100101;
			public string Encrypt(string plainText, string key)
			{
				if (string.IsNullOrEmpty(plainText))
				{
					throw new ArgumentNullException("plainText");
				}

				// Get the decryption key from the machine key section of the web.config
				var secureStringKey = new SecureString();

				// ***Note: making call here to hide additional encryption key from reflection.
				var emb = new ExceptionMessageBase();
				byte[] salt;
				new RNGCryptoServiceProvider().GetBytes(salt = new byte[_saltSize]);
				// *** Note storing in secure string to hide the encryption key in memory.
				secureStringKey = emb.ConvertStringToSecureString(key);
				using (var keyDerivationFunction = new Rfc2898DeriveBytes(emb.ConvertSecureStringToString(secureStringKey), salt, _iterationCount, HashAlgorithmName.SHA512))
				{
					var saltBytes = keyDerivationFunction.Salt;
					var keyBytes = keyDerivationFunction.GetBytes(32);
					var ivBytes = keyDerivationFunction.GetBytes(16);
					using (var aesManaged = new AesManaged())
					{
						aesManaged.KeySize = 256;
						using (var encryptor = aesManaged.CreateEncryptor(keyBytes, ivBytes))
						{
							MemoryStream memoryStream = null;
							CryptoStream cryptoStream = null;
							return WriteMemoryStream(plainText, ref saltBytes, encryptor, ref memoryStream, ref cryptoStream);
						}
					}
				}
			}
			public string Decrypt(string cipherText, string key)
			{
				if (string.IsNullOrEmpty(cipherText))
				{
					throw new ArgumentNullException("cipherText");
				}

				// Get the decryption key from the machine key section of the web.config
				var secureStringKey = new SecureString();

				// ***Note: making call here to hide additional encryption key from reflection.
				var emb = new ExceptionMessageBase();

				// *** Note storing in secure string to hide the encryption key in memory.
				secureStringKey = emb.ConvertStringToSecureString(key);
				var allTheBytes = Convert.FromBase64String(cipherText);
				var saltBytes = allTheBytes.Take(_saltSize).ToArray();
				var ciphertextBytes = allTheBytes.Skip(_saltSize).Take(allTheBytes.Length - _saltSize).ToArray();
				using (var keyDerivationFunction = new Rfc2898DeriveBytes(emb.ConvertSecureStringToString(secureStringKey), saltBytes, _iterationCount, HashAlgorithmName.SHA512))
				{
					var keyBytes = keyDerivationFunction.GetBytes(32);
					var ivBytes = keyDerivationFunction.GetBytes(16);
					return DecryptWithAes(ciphertextBytes, keyBytes, ivBytes);
				}
			}

			private string WriteMemoryStream(string plainText, ref byte[] saltBytes, ICryptoTransform encryptor, ref MemoryStream memoryStream, ref CryptoStream cryptoStream)
			{
				try
				{
					memoryStream = new MemoryStream();
					try
					{
						cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write);
						using (var streamWriter = new StreamWriter(cryptoStream))
						{
							streamWriter.Write(plainText);
						}
					}
					finally
					{
						if (cryptoStream != null)
						{
							cryptoStream.Dispose();
						}
					}
					var cipherTextBytes = memoryStream.ToArray();
					Array.Resize(ref saltBytes, saltBytes.Length + cipherTextBytes.Length);
					Array.Copy(cipherTextBytes, 0, saltBytes, _saltSize, cipherTextBytes.Length);
					return Convert.ToBase64String(saltBytes);
				}
				finally
				{
					if (memoryStream != null)
					{
						memoryStream.Dispose();
					}
				}
			}
			private static string DecryptWithAes(byte[] ciphertextBytes, byte[] keyBytes, byte[] ivBytes)
			{
				using (var aesManaged = new AesManaged())
				{
					using (var decryptor = aesManaged.CreateDecryptor(keyBytes, ivBytes))
					{
						MemoryStream memoryStream = null;
						CryptoStream cryptoStream = null;
						StreamReader streamReader = null;
						try
						{
							memoryStream = new MemoryStream(ciphertextBytes);
							cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);
							streamReader = new StreamReader(cryptoStream);
							return streamReader.ReadToEnd();
						}
						finally
						{
							if (memoryStream != null)
							{
								memoryStream.Dispose();
								memoryStream = null;
							}
						}
					}
				}
			}
		}

		public class ExceptionMessageBase
        {
            /// <summary>
            ///     Allows you to create new secure strings.
            ///     Hides the encryption key from prying eyes.
            ///     Note this is the LicenseUniqueSecurityKey (AKA the last part of the license key.
            /// </summary>
            /// <returns></returns>
            public SecureString ConvertStringToSecureString(string clientKey)
            {
                var secureStr = new SecureString();
                //Note: (Security) The encryption key is part of the users unique id. And setup the GUID to have a consistent naming convention with the clients. 
                var value = @"7-Zl=M3&6L~Pv%d)J9A,8^V1_QjF5>0$w\g4Wt:2q[D+u@i<EaXrNc?zGmY}v(a2H=0cA?8]9d3>5t4,1S7`m6_lWwL.Vi/q[E<r+nF:eZ}B%g^pGjOs-x*Q" + clientKey.ToLower(); // Client Key should always be lowercase but the super secret key needs to be upper case. 
                if (value.Length > 0)
                {
                    foreach (var c in value.ToCharArray())
                    {
                        secureStr.AppendChar(c);
                    }
                }
                return secureStr;
            }
            /// <summary>
            ///     Converts a SecureString to a string.
            /// </summary>
            /// <param name="ss"></param>
            /// <returns></returns>
            public string ConvertSecureStringToString(SecureString ss)
            {
                var ptr = Marshal.SecureStringToBSTR(ss);
                try
                {
                    return (Marshal.PtrToStringBSTR(ptr));
                }
                finally
                {
                    Marshal.ZeroFreeBSTR(ptr);
                }
            }

            //public static string ConvertToUnsecureString(this SecureString securePassword)
            //{
            //    if (securePassword == null)
            //        throw new ArgumentNullException("securePassword");

            //    IntPtr unmanagedString = IntPtr.Zero;
            //    try
            //    {
            //        unmanagedString = Marshal.SecureStringToGlobalAllocUnicode(securePassword);
            //        return Marshal.PtrToStringUni(unmanagedString);
            //    }
            //    finally
            //    {
            //        Marshal.ZeroFreeGlobalAllocUnicode(unmanagedString);
            //    }
            //}
            /// <summary>
            ///     Converts a SecureString to bytes.
            /// </summary>
            /// <param name="ss"></param>
            /// <returns></returns>
            public byte[] ConvertSecureStringToKeyBytes(SecureString ss)
            {
                var ptr = Marshal.SecureStringToBSTR(ss);
                try
                {
                    return Encoding.UTF8.GetBytes((Marshal.PtrToStringBSTR(ptr)));
                }
                finally
                {
                    Marshal.ZeroFreeBSTR(ptr);
                }
            }
        }
        
    }
}
