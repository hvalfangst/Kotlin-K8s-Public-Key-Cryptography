package hvalfangst.crypto

import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter

@Configuration
class KubernetesSecretsConfig(
    @Value("\${k8s.number}") final val serverNumber: String,
    @Value("\${k8s.path}") final val keyStorePath: String,
    @Value("\${k8s.password}") final val keyStorePassword: String,
    @Value("\${k8s.alias}") final val keyAlias: String,
    @Value("\${k8s.serviceNameCounterpart}") final val serviceNameCounterpart: String,
    @Value("\${k8s.publicKeyCounterpart}") final val publicKeyCounterpart: String,
    ) : WebSecurityConfigurerAdapter() {
    private val logger = LoggerFactory.getLogger(Configuration::class.java)

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
