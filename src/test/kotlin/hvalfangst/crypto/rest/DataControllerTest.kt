package hvalfangst.crypto.rest

import com.fasterxml.jackson.databind.ObjectMapper
import hvalfangst.crypto.EncryptionService
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.Mockito.`when`
import org.mockito.Mockito.verify
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest
import org.springframework.boot.test.mock.mockito.MockBean
import org.springframework.http.MediaType
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders
import org.springframework.test.web.servlet.result.MockMvcResultMatchers
import org.springframework.test.web.servlet.setup.MockMvcBuilders

@WebMvcTest(DataController::class)
class DataControllerTest {
    @MockBean
    private lateinit var encryptionService: EncryptionService

    private lateinit var mockMvc: MockMvc

    @BeforeEach
    fun setup() {
        mockMvc = MockMvcBuilders.standaloneSetup(DataController(encryptionService))
            .build()
    }

    @Test
    fun testMessageEndpoint() {
        val encryptedData = "encryptedData"
        val signature = "signature"
        val objectMapper = ObjectMapper()
        val request = MessageBody(encryptedData = encryptedData, signature = signature)

        `when`(encryptionService.verifySignature(encryptedData, signature)).thenReturn(true)
        `when`(encryptionService.decrypt(encryptedData)).thenReturn("decryptedData")
        `when`(encryptionService.encrypt("The message you sent consists of ${encryptedData.length} characters")).thenReturn("encryptedResponse")
        `when`(encryptionService.sign("encryptedResponse")).thenReturn("responseSignature")

        mockMvc.perform(
            MockMvcRequestBuilders.post("/data/message")
                .content(objectMapper.writeValueAsString(request))
                .contentType(MediaType.APPLICATION_JSON)
        )
            .andExpect(MockMvcResultMatchers.status().isOk)
            .andExpect(MockMvcResultMatchers.jsonPath("$.statusCode").value("ACCEPTED"))
            .andExpect(MockMvcResultMatchers.jsonPath("$.description").value("Data encrypted and signed"))
            .andExpect(MockMvcResultMatchers.jsonPath("$.encryptedData").value("encryptedResponse"))
            .andExpect(MockMvcResultMatchers.jsonPath("$.signature").value("responseSignature"))

        verify(encryptionService).verifySignature(encryptedData, signature)
        verify(encryptionService).decrypt(encryptedData)
        verify(encryptionService).encrypt("The message you sent consists of 13 characters")
        verify(encryptionService).sign("encryptedResponse")
    }
}
