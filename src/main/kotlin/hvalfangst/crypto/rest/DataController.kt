package hvalfangst.crypto.rest

import com.fasterxml.jackson.databind.ObjectMapper
import hvalfangst.crypto.EncryptionService
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.*
import org.springframework.web.bind.annotation.*
import org.springframework.web.client.RestTemplate

data class MessageBody(
    val statusCode: HttpStatus = HttpStatus.OK,
    val description: String = "",
    val encryptedData: String? = null,
    val signature: String? = null
) {
    // Default constructor for Jackson deserialization
    constructor() : this(HttpStatus.OK, "", null, null)
}

@RestController
@RequestMapping("/data")
class DataController(@Autowired private val encryptionService: EncryptionService) {

    private val logger = LoggerFactory.getLogger(DataController::class.java)
    private val objectMapper = ObjectMapper()

    @PostMapping("/message")
    fun message(@RequestBody request: MessageBody): ResponseEntity<MessageBody> {
        val encryptedData = request.encryptedData
        val signature = request.signature
        val isSignatureValid = encryptedData?.let {
            signature?.let { it1 -> encryptionService.verifySignature(it, it1)}
        }

        // Verify the signature of the encrypted data using the sender's public key
       if (!isSignatureValid!!) {
           logger.error("\n\n - - - - [Invalid Signature] - - - - \n\n")
           return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
               MessageBody(
                   HttpStatus.BAD_REQUEST,
                   "Invalid Signature",
                   null,
                   null
               )
           )
       } else if (isSignatureValid) {
           logger.info("\n\n [SIGNATURE VALID] \n\n")
       }

        // Decrypt the incoming encrypted data using the private key
        val decryptedData = encryptionService.decrypt(encryptedData)
        logger.info("\n\n |Received encrypted data: $encryptedData| \n\n")
        logger.info("\n\n |Decrypted data: $decryptedData| \n\n")

        val amountCharacters = decryptedData.length

        // Process the decrypted data and generate a response
        val response = "The message you sent consists of $amountCharacters characters"

        // Encrypt the response using the recipient's public key
        val encryptedResponse = encryptionService.encrypt(response)
        logger.info("\n\n |Raw response: $response| \n\n")
        logger.info("\n\n |Encrypted response: $encryptedResponse| \n\n")

        // Sign the encrypted response using the private key
        val responseSignature = encryptionService.sign(encryptedResponse)
        logger.info("\n\n |Response signature: $responseSignature| \n\n")

        // Return the signed encrypted response
        return ResponseEntity.ok().body(
            MessageBody(
            HttpStatus.ACCEPTED,
                "Data encrypted and signed",
                encryptedResponse,
                responseSignature
             )
        )
    }

    @PostMapping("/messageCounterpart")
    fun messageCounterpart(@RequestBody data: String): ResponseEntity<String> {
        val restTemplate = RestTemplate()
        val url = "http://${encryptionService.serviceNameCounterpart}/data/message"
        val requestHeaders = HttpHeaders()
        val encryptedData = encryptionService.encrypt(data)
        val signature = encryptionService.sign(encryptedData)

        logger.info("\n\n |Raw request data: $data| \n\n")
        logger.info("\n\n |Encrypted request data: $encryptedData| \n\n")
        logger.info("\n\n |Signature for encrypted data: [$signature]| \n\n")

        // Wrap encrypted data and its corresponding signature in the MessageRequest type
        val messageRequest = MessageBody(
            HttpStatus.ACCEPTED,
            "Initial data encrypted and signed",
            encryptedData,
            signature)

        val requestBody = HttpEntity(messageRequest, requestHeaders)

        val response: ResponseEntity<MessageBody> = restTemplate.exchange(url, HttpMethod.POST, requestBody, MessageBody::class.java)
        val body = response.body
        val responseSignature: String? = body?.signature
        val responseEncryptedData: String? = body?.encryptedData
        val isSignatureValid = responseEncryptedData?.let {
            responseSignature?.let { it1 -> encryptionService.verifySignature(it, it1)}
        }

        if (!isSignatureValid!!) {
            logger.error("\n\n - - - - [Invalid Signature] - - - - \n\n")
            return ResponseEntity.badRequest().body("Invalid Signature")
        } else if (isSignatureValid) {
            logger.info("\n\n [SIGNATURE VALID] \n\n")
        }

        logger.info("\n - - - - |Encrypted Response Data: [$responseEncryptedData]| - - - - \n")
        val decryptedResponseData = encryptionService.decrypt(responseEncryptedData)
        logger.info("\n - - - - |Decrypted Response Data: [$decryptedResponseData]| - - - - \n")

        return ResponseEntity.ok(decryptedResponseData)
    }

    init {
        logger.info("\n\n - - - - |Initializing Controller| - - - - \n\n")
    }
}