package hello.security;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.cas.authentication.CasAssertionAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * Authenticate a user from the database.
 */
public class CustomUserDetailService implements AuthenticationUserDetailsService<CasAssertionAuthenticationToken> {

    private final Logger log = LoggerFactory.getLogger(CustomUserDetailService.class);

    private Set<String> admins;

    public CustomUserDetailService() {
        super();
    }

    /**
     * @param admins
     */
    public CustomUserDetailService(Set<String> admins) {
        super();
        this.admins = admins;
    }

    @Override
    public UserDetails loadUserDetails(CasAssertionAuthenticationToken token) throws UsernameNotFoundException {
        String login = token.getPrincipal().toString();
        String lowercaseLogin = login.toLowerCase();

        log.debug("Authenticating '{}'", login);
        List<GrantedAuthority> grantedAuthorities = new ArrayList<GrantedAuthority>();

        if (admins != null && admins.contains(lowercaseLogin)) {
            grantedAuthorities.add(new SimpleGrantedAuthority(AuthoritiesConstants.ADMIN));
        } else {
            grantedAuthorities.add(new GrantedAuthority() {
                private static final long serialVersionUID = 1L;

                @Override
                public String getAuthority() {
                    return AuthoritiesConstants.USER;
                }
            });
        }

        return new AppUserDetails(lowercaseLogin, grantedAuthorities);
    }
}