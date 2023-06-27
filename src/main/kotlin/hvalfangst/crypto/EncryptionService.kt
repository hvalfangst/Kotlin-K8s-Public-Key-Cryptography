package hvalfangst.crypto

import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import java.io.File
import java.io.FileInputStream
import java.io.InputStream
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.*
import javax.crypto.Cipher

@Service
class EncryptionService(kubernetesSecretsConfig: KubernetesSecretsConfig) {
    private val logger = LoggerFactory.getLogger(EncryptionService::class.java)
    private val rsaCipher: Cipher = Cipher.getInstance("RSA")
    private val rsaSignature: Signature = Signature.getInstance("SHA256withRSA")

    // Counterpart refers to the other container in the cluster
    private var calleePublicKey: PublicKey? = null

    private var privateKey: PrivateKey? = null
    final var serverNumber: String? = null
    final var serviceNameCounterpart: String? = null

    fun encrypt(data: String): String {
        rsaCipher.init(Cipher.ENCRYPT_MODE, calleePublicKey)
        val encryptedBytes = rsaCipher.doFinal(data.toByteArray())
        return Base64.getEncoder().encodeToString(encryptedBytes)
    }

    fun decrypt(encryptedData: String): String {
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey)
        val decryptedBytes = rsaCipher.doFinal(Base64.getDecoder().decode(encryptedData))
        return String(decryptedBytes)
    }

    fun sign(data: String): String {
        rsaSignature.initSign(privateKey)
        rsaSignature.update(data.toByteArray())
        val signatureBytes = rsaSignature.sign()
        return Base64.getEncoder().encodeToString(signatureBytes)
    }

    fun verifySignature(data: String, signature: String): Boolean {
        rsaSignature.initVerify(calleePublicKey)
        rsaSignature.update(data.toByteArray())
        val signatureBytes = Base64.getDecoder().decode(signature)
        return rsaSignature.verify(signatureBytes)
    }

    private fun initKeyStore(kubernetesSecretsConfig: KubernetesSecretsConfig): KeyStore {
        val keyStore = KeyStore.getInstance("PKCS12")
        val keystoreFile = File(kubernetesSecretsConfig.keyStorePath)
        val inputStream: InputStream = FileInputStream(keystoreFile)
        keyStore.load(inputStream, kubernetesSecretsConfig.keyStorePassword.toCharArray())
        return keyStore
    }

    private fun initPublicKey(kubernetesSecretsConfig: KubernetesSecretsConfig) {
        try {
            logger.info(kubernetesSecretsConfig.publicKeyCounterpart)

            val certificateData = kubernetesSecretsConfig.publicKeyCounterpart
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replace("\\s".toRegex(), "")

            val certificateBytes = Base64.getDecoder().decode(certificateData)

            val certificateFactory = CertificateFactory.getInstance("X.509")
            val certificate = certificateFactory.generateCertificate(certificateBytes.inputStream()) as X509Certificate
            val publicKey = certificate.publicKey

            this.calleePublicKey = publicKey

            val calleeServerNumber: String = if (serverNumber == "1") "2" else "1"
            logger.info("\n\n - - - |Public Key for server #$calleeServerNumber has been set| - - - \n\n")
        } catch (e: Exception) {
            logger.error("Error occurred while initializing the public key: {}", e.message)
        }
    }

    private fun initPrivateKey(
        keyStore: KeyStore,
        kubernetesSecretsConfig: KubernetesSecretsConfig
    ) {
        val privateKey = keyStore.getKey(
            kubernetesSecretsConfig.keyAlias,
            kubernetesSecretsConfig.keyStorePassword.toCharArray()
        ) as PrivateKey
        this.privateKey = privateKey
        logger.info("\n\n - - - |Private Key for server #${serverNumber} has been set| - - - \n\n")
    }

    init {
        logger.info("\n\n - - - - |Initializing EncryptionService| - - - - \n\n")
        serverNumber = kubernetesSecretsConfig.serverNumber
        serviceNameCounterpart = kubernetesSecretsConfig.serviceNameCounterpart

        logger.info("\n\n Server Number: $serverNumber \n\n")
        logger.info("\n\n Other Server IP: $serviceNameCounterpart \n\n")

        val keyStore = initKeyStore(kubernetesSecretsConfig)

        logger.info("\n\n - - - - |KeyStore has been Loaded| - - - - \n\n")

        try {
            initPrivateKey(keyStore, kubernetesSecretsConfig)
            initPublicKey(kubernetesSecretsConfig)
        } catch (e: Exception) {
            logger.error("Error occurred while retrieving keys from keystore: {}", e.message)
        }
    }
}