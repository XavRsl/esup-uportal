package fr.insa_lyon.cas.client.session;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.jasig.cas.client.session.SessionMappingStorage;
import org.jasig.cas.client.session.SingleSignOutHandler;
import org.jasig.cas.client.util.AbstractConfigurationFilter;
import org.jasig.cas.client.util.CommonUtils;
import org.jasig.cas.client.util.XmlUtils;

public class SingleSignOutFilter extends AbstractConfigurationFilter {

	private static final SingleSignOutHandler handler = new SingleSignOutHandler();
	private String artifactParameterName;
	private String logoutParameterName;
	
	/* forwarding request */
	private List<String> logoutForwardTo = new ArrayList<String>();
	private int logoutForwardReadTimeout = 1000;
	private int logoutForwardConnectionTimeout = 1000;
	private boolean logoutForwardIfSessionExists = false;
	private boolean logoutForwardFollowRedirect = false;
	private static ExecutorService EXECUTOR_SERVICE = Executors.newFixedThreadPool(100);
	
	@Override
	public void destroy() {
		EXECUTOR_SERVICE.shutdown();
	}

	@Override
	public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse,
			FilterChain filterChain) throws IOException, ServletException {
		final HttpServletRequest request = (HttpServletRequest) servletRequest;
		
		if ( request.getAttribute(SingleSignOutFilter.class.getName()) == null ) {
			request.setAttribute(SingleSignOutFilter.class.getName(), Boolean.TRUE);
		} else {
			filterChain.doFilter(servletRequest, servletResponse);
			return;
		}
		
		if ( handler.isLogoutRequest(request) ) {
			final String logoutMessage = CommonUtils.safeGetParameter(request, this.logoutParameterName);
	        //if (log.isTraceEnabled()) {
	            System.out.println ("Logout request:\n" + logoutMessage);
	        //}
		        
	        final String token = XmlUtils.getTextForElement(logoutMessage, "SessionIndex");
					System.out.println ("This is the token:\n" + token);
	        if (CommonUtils.isNotBlank(token)) {
	        	//final HttpSession sess = handler.getSessionMappingStorage();
						//System.out.println ("Temporary Session:\n" + sess);
	        	final HttpSession session = handler.getSessionMappingStorage().removeSessionByMappingId(token);
						System.out.println ("This is the session:\n" + session);

	        	if (session != null) {
	        		String sessionID = session.getId();

	                //if (log.isDebugEnabled()) {
	                    System.out.println ("Invalidating session [" + sessionID + "] for token [" + token + "]");
	                //}
	                try {
	                    session.invalidate();
	                } catch (final IllegalStateException e) {
	                    log.debug("Error invalidating session.", e);
	                }
	            }
	        	if ( session == null || logoutForwardIfSessionExists ) {
	        		doForwardLogoutRequest(request, logoutMessage);
	        	}
	        }
	        return; // do not continue the filter chain
		}

        filterChain.doFilter(servletRequest, servletResponse);
	}

	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
		if (!isIgnoreInitConfiguration()) {
			this.artifactParameterName = getPropertyFromInitParams(filterConfig, "artifactParameterName", "ticket");
			this.logoutParameterName = getPropertyFromInitParams(filterConfig, "logoutParameterName", "logoutRequest");
			handler.setArtifactParameterName(this.artifactParameterName);
			handler.setLogoutParameterName(this.logoutParameterName);
			//
			this.logoutForwardReadTimeout = Integer.valueOf(getPropertyFromInitParams(filterConfig, "logoutForwardReadTimeout", "1000"));
			this.logoutForwardConnectionTimeout = Integer.valueOf(getPropertyFromInitParams(filterConfig, "logoutForwardConnectionTimeout", "1000"));
			this.logoutForwardFollowRedirect = Boolean.valueOf(getPropertyFromInitParams(filterConfig, "logoutForwardFollowRedirect", "false"));
			this.logoutForwardIfSessionExists = Boolean.valueOf(getPropertyFromInitParams(filterConfig, "logoutForwardIfSessionExists", "false"));
			String[] fwdTo = getPropertyFromInitParams(filterConfig, "logoutForwardTo", "").trim().split(";");
			for ( String f : fwdTo ) {
				if ( f.trim().length() > 0 )
					this.logoutForwardTo.add(f.trim());
			}
		}
		handler.init();
	}

	public void setArtifactParameterName(final String name) {
		handler.setArtifactParameterName(name);
	}
	    
	public void setLogoutParameterName(final String name) {
		handler.setLogoutParameterName(name);
	}

	public void setSessionMappingStorage(final SessionMappingStorage storage) {
		handler.setSessionMappingStorage(storage);
	}
	
	public static SingleSignOutHandler getSingleSignOutHandler() {
		return handler;
	}
	
	protected void doForwardLogoutRequest(HttpServletRequest request, String logoutMessage) {
		if ( SingleSignOutFilterUtils.isForwardedLogout(request) || logoutForwardTo.size() <= 0 ) 
			return;
		for ( String url : logoutForwardTo ) {
			if ( log.isDebugEnabled() )
				log.debug("About to send SSO Logout to "+url);
			sendMessageToEndPoint(url, logoutMessage, true);
		}
	}
	
	public boolean sendMessageToEndPoint(final String url, final String message, final boolean async) {
		final Future<Boolean> result = EXECUTOR_SERVICE.submit(
				new SingleSignOutMessageSender(url, message, 
						this.logoutForwardReadTimeout, 
						this.logoutForwardConnectionTimeout, 
						this.logoutForwardFollowRedirect)
				);
		if (async) {
			return true;
		}
		try {
			return result.get();
		} catch (final Exception e) {
			return false;
		}
	}
}
