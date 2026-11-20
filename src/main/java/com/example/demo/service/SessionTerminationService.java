package com.example.demo.service;

import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

/**
 * Encerra todas as sessões ativas de um usuário. Usado após a redefinição de senha:
 * quem estava logado com a senha antiga (inclusive um invasor) perde o acesso.
 */
@Service
public class SessionTerminationService {

    private final SessionRegistry sessionRegistry;

    public SessionTerminationService(SessionRegistry sessionRegistry) {
        this.sessionRegistry = sessionRegistry;
    }

    /** @return quantidade de sessões expiradas */
    public int expireAllSessions(String email) {
        if (email == null) {
            return 0;
        }
        int expired = 0;
        for (Object principal : sessionRegistry.getAllPrincipals()) {
            String name = principal instanceof UserDetails details ? details.getUsername() : String.valueOf(principal);
            if (email.equalsIgnoreCase(name)) {
                for (SessionInformation info : sessionRegistry.getAllSessions(principal, false)) {
                    info.expireNow();
                    expired++;
                }
            }
        }
        return expired;
    }
}
