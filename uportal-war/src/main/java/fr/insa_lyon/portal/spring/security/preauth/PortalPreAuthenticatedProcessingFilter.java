package fr.insa_lyon.portal.spring.security.preauth;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.jasig.cas.client.util.CommonUtils;
import org.jasig.portal.security.IPerson;
import org.jasig.portal.security.ISecurityContext;
import org.jasig.portal.security.provider.cas.ICasSecurityContext;

import fr.insa_lyon.cas.client.session.SingleSignOutFilter;

public class PortalPreAuthenticatedProcessingFilter extends org.jasig.portal.spring.security.preauth.PortalPreAuthenticatedProcessingFilter {
	private String artifactParameterName = "ticket";

	/* (non-Javadoc)
	 * @see org.jasig.portal.spring.security.preauth.PortalPreAuthenticatedProcessingFilter#afterPortalAuthentication(javax.servlet.http.HttpServletRequest, org.jasig.portal.security.IPerson)
	 */
	@Override
	protected void afterPortalAuthentication(HttpServletRequest request,
			IPerson person) {
		if ( person != null && person.getSecurityContext().isAuthenticated() ) {
			System.out.println("Person OK");
			ISecurityContext ctx = ( person.getSecurityContext().getAuthType() == ICasSecurityContext.CAS_AUTHTYPE ) ? person.getSecurityContext() : person.getSecurityContext().getSubContext("cas");
			if ( ctx != null && ctx.isAuthenticated() ) {
				System.out.println("ctx not null");
				System.out.println("Requested Sessions ID\n" + request.getRequestedSessionId());
				System.out.println("is token Request ?\n" + SingleSignOutFilter.getSingleSignOutHandler().isTokenRequest(request));
				if ( SingleSignOutFilter.getSingleSignOutHandler().isTokenRequest(request) ) {
					HttpSession session = request.getSession(false);
					final String token = CommonUtils.safeGetParameter(request, this.artifactParameterName);
					System.out.println("token\n" + token);
					System.out.println("session\n" + session.getId());
					if ( session != null && token != null ) {
						try {
							SingleSignOutFilter.getSingleSignOutHandler().getSessionMappingStorage().removeBySessionById(session.getId());
						} catch ( final Exception e ) {
							// ignore
						}
						SingleSignOutFilter.getSingleSignOutHandler().getSessionMappingStorage().addSessionById(token, session);
					}
				}
			}
		}
	  //super.afterPortalAuthentication(request, person);
	}

	

}
