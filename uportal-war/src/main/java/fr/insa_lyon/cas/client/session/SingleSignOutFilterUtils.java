package fr.insa_lyon.cas.client.session;

import javax.servlet.http.HttpServletRequest;

public class SingleSignOutFilterUtils {

	public static final String X_FORWARDED_LOGOUT_HEADER = "X-Forwarded-SSO-Logout";
	
	public static boolean isForwardedLogout(final HttpServletRequest request) {
		return ( request.getHeader(X_FORWARDED_LOGOUT_HEADER) != null );
	}
	

}
