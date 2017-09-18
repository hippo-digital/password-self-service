import java.net.URL;
import java.net.URISyntaxException;
import java.net.MalformedURLException;

import com.gemplus.gemauth.api.GATicket;
import netscape.javascript.JSObject;

public class openNhsAuthApplet extends java.applet.Applet {
    private String successPath = "ok";
    private String failurePath = "failed";

    public void start() {
        String ticket = null;

        try {
            this.successPath = this.getParameter("successPath");
            this.failurePath = this.getParameter("failurePath");
        }
        catch (Exception ex) {
            System.out.println("Message=Failed to load parameters, Error=" + ex);
            return;
        }

        try {
            GATicket gATicket = new GATicket();
            ticket = gATicket.getNewTicket();
            this.setCookie("ticket", ticket, false);
        }
        catch (Exception ex) {
            System.out.println("Message=Failed to get ticket from GATicket, Error=" + ex);
            return;
        }
    }

    private void setCookie(String name, String value, boolean secure) throws URISyntaxException
	{
        String cookie = name + "=" + value;

        if (secure)
        {
            cookie += "; secure";
        }

        JSObject window = JSObject.getWindow(this);
        JSObject document = (JSObject)window.getMember("document");
        document.setMember("cookie", cookie);
	}
}

