import hvalfangst.crypto.EncryptionService
import hvalfangst.crypto.EnvironmentConfiguration
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.Mock
import org.mockito.Mockito.`when`
import org.mockito.MockitoAnnotations
import java.io.File
import java.io.FileInputStream
import java.security.*

class EncryptionServiceTest {

    @Mock
    private lateinit var kubernetesSecretsConfig: EnvironmentConfiguration
    @Mock
    private lateinit var encryptionService: EncryptionService
    @Mock
    private lateinit var publicKeyCounterpart: PublicKey
    @Mock
    private lateinit var privateKey: PrivateKey

    @BeforeEach
    fun setUp() {
        MockitoAnnotations.openMocks(this)

        // Create a key with size of 2048 and extract private and public keys
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(2048)
        val keyPair = keyPairGenerator.generateKeyPair()
        publicKeyCounterpart = keyPair.public
        privateKey = keyPair.private


        println("Public Key Counterpart: $publicKeyCounterpart")
        println("Private Key: $privateKey")

        // Load test keystore and set the associated path in our mocked config variables
        val keystoreFilePath = javaClass.classLoader.getResource("local_keystore.p12")?.file
        val keystoreFile = keystoreFilePath?.let { File(it) }
        val keyStore = KeyStore.getInstance("PKCS12")
        val inputStream: FileInputStream? = keystoreFile?.let { FileInputStream(it) }
        keyStore.load(inputStream, "changeit".toCharArray())

        `when`(kubernetesSecretsConfig.getKeyStorePath()).thenReturn(keystoreFilePath)
        `when`(kubernetesSecretsConfig.getKeyStorePassword()).thenReturn("changeit")
        `when`(kubernetesSecretsConfig.getKeyAlias()).thenReturn("server_1_key")
        `when`(kubernetesSecretsConfig.getServerNumber()).thenReturn("1")
        `when`(kubernetesSecretsConfig.getServiceNameCounterpart()).thenReturn("service2")

        // Set variables utilized in EncryptionService
        encryptionService = EncryptionService(kubernetesSecretsConfig)
        encryptionService.serverNumber = kubernetesSecretsConfig.getServerNumber()
        encryptionService.serviceNameCounterpart = kubernetesSecretsConfig.getServiceNameCounterpart()
        encryptionService.privateKey = privateKey
        encryptionService.publicKeyCounterpart = publicKeyCounterpart
    }

    @Test
    fun encryptDecryptTest() {
        val data = "Hello, World!"
        val encryptedData = encryptionService.encrypt(data)
        print("\n[Encrypted Data]\n $encryptedData\n[Encrypted Data]\n")
        val decryptedData = encryptionService.decrypt(encryptedData)
        print("\n[Decrypted Data]: $decryptedData \n\n")

        assertEquals(data, decryptedData)
    }

    @Test
    fun signVerifySignatureTest() {
        val data = "Hello, World!"
        val signature = encryptionService.sign(data)
        print("\n[Signature]\n $signature\n[Signature]\n")
        val isSignatureValid = encryptionService.verifySignature(data, signature)

        assertEquals(true, isSignatureValid)
    }
}
