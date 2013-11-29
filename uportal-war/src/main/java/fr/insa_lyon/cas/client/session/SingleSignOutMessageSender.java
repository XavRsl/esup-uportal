package fr.insa_lyon.cas.client.session;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.concurrent.Callable;

public class SingleSignOutMessageSender implements Callable<Boolean> {

	private int connectionTimeout;
	private String message;
	private String url;
	private int readTimeout;
	private boolean followRedirect;

	public SingleSignOutMessageSender(String url, String message, int readTimeout, int connectionTimeout, boolean followRedirect) {
		this.url = url;
		this.message = message;
		this.readTimeout = readTimeout;
		this.connectionTimeout = connectionTimeout;
		this.followRedirect = followRedirect;
	}

	@Override
	public Boolean call() throws Exception {
		HttpURLConnection con = null;
		BufferedReader in = null;
		try {
			final URL forwardUrl = new URL(url);
			final String output = "logoutRequest=" + URLEncoder.encode(message, "UTF-8");
			
			con = (HttpURLConnection)forwardUrl.openConnection();
			con.setDoInput(true);
            con.setDoOutput(true);
            // do not follow redirect; simply send request
            con.setInstanceFollowRedirects(this.followRedirect);
            con.setRequestMethod("POST");
            con.setReadTimeout(this.readTimeout);
            con.setConnectTimeout(this.connectionTimeout);
            con.setRequestProperty(SingleSignOutFilterUtils.X_FORWARDED_LOGOUT_HEADER, "1");
            con.setRequestProperty("Content-Length", Integer.toString(output.getBytes().length));
            con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            final DataOutputStream printout = new DataOutputStream(con.getOutputStream());
            printout.writeBytes(output);
            printout.flush();
            printout.close();
            
            @SuppressWarnings("unused")
			int responseCode = con.getResponseCode();
            /*
            in = new BufferedReader(new InputStreamReader(con.getInputStream()));
            while (in.readLine() != null) {
                // nothing to do
            }*/
            return true;
		} catch ( Exception e ) {
			//log.error("unable to forward logout request to :"+url,e);
			return false;
		} finally {
			if ( in != null ) {
				try {
					in.close();
				} catch (IOException e) {
					// do nothing
				}
			}
			if ( con != null ) {
				con.disconnect();
			}
		}
	}

}
