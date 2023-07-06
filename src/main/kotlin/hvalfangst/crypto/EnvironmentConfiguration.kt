package hvalfangst.crypto

import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter

@Configuration
class EnvironmentConfiguration(
    @Value("\${env.number}") private val serverNumber: String,
    @Value("\${env.path}") private val keyStorePath: String,
    @Value("\${env.password}") private val keyStorePassword: String,
    @Value("\${env.alias}") private val keyAlias: String,
    @Value("\${env.serviceNameCounterpart}") private val serviceNameCounterpart: String,
    @Value("\${env.publicKeyCounterpart}") private val publicKeyCounterpart: String,
    ) : WebSecurityConfigurerAdapter() {
    private val logger = LoggerFactory.getLogger(Configuration::class.java)

    fun getServerNumber(): String {
        return serverNumber
    }

    fun getKeyStorePath(): String {
        return keyStorePath
    }

    fun getKeyStorePassword(): String {
        return keyStorePassword
    }

    fun getKeyAlias(): String {
        return keyAlias
    }

    fun getServiceNameCounterpart(): String {
        return serviceNameCounterpart
    }

    fun getPublicKeyCounterpart(): String {
        return publicKeyCounterpart
    }

    override fun configure(http: HttpSecurity) {
        http.authorizeRequests()
            .antMatchers("/data/message", "/data/messageCounterpart").permitAll()
            .anyRequest().authenticated()
            .and()
            .httpBasic()
            .and()
            .csrf().disable()
    }

    init {
        logger.info("\n\n - - - - [Initializing Server #${serverNumber}] - - - - \n\n")
    }
}
