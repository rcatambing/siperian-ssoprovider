package com.axa.sso;

import com.siperian.bdd.security.LoginCredentials;
import com.siperian.bdd.security.LoginProvider;
import com.siperian.bdd.security.LoginProviderException;
import java.io.InputStream;
import java.lang.invoke.MethodHandles;
import java.text.Format;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Enumeration;
import java.util.Properties;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SSOLoginProvider implements LoginProvider {
  private static final Logger LOG = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass().getSimpleName());
  
  private static final String LOGIN_TARGET = "/e360/mdm/entity360view/";
  
  private static final String LOGOUT_TARGET = "/mdm/entity360view/?logoutParam=gotoLogoutPage";
  
  private static final String SITEMINDER_LOGOUT = "/bdd/logoutB.jsf";
  
  private static final Format DEFAULT_DATE_FMT = new SimpleDateFormat("YYYYMMDD HH:mm:ss");
  
  public void redirectToProviderLoginPage(HttpServletRequest paramHttpServletRequest, HttpServletResponse paramHttpServletResponse, String paramString) throws LoginProviderException {
    LOG.info("redirectToProviderLoginPage----------Executing" + Thread.currentThread().getName());
    String str = (paramHttpServletRequest.getContextPath() != null) ? paramHttpServletRequest.getContextPath() : "";
    LOG.info("PATH : " + str);
    StringBuilder stringBuilder = new StringBuilder();
    HttpSession httpSession = paramHttpServletRequest.getSession();
    httpSession.setAttribute("redirectToProviderLoginPageCalled", "Y");
    LOG.info("Session details start---------------------");
    LOG.info("Session ID : " + httpSession.getId() + " isNew : " + httpSession.isNew() + " Last access time : " + httpSession.getLastAccessedTime() + " Inactive interval : " + httpSession.getMaxInactiveInterval());
    Enumeration<String> enumeration = httpSession.getAttributeNames();
    stringBuilder = new StringBuilder();
    while (enumeration.hasMoreElements()) {
      String str1 = enumeration.nextElement();
      stringBuilder.append("{[Name]:");
      stringBuilder.append(str1);
      stringBuilder.append("[Value]:");
      stringBuilder.append(paramHttpServletRequest.getParameter(httpSession.getAttribute(str1).toString()));
      stringBuilder.append("}");
    } 
    LOG.info(stringBuilder.toString());
    LOG.info("Session details end---------------------");
    try {
      LOG.info("request.getContextPath() : " + str);
      if ("gotoLogoutPage".equalsIgnoreCase(paramHttpServletRequest.getParameter("logoutParam"))) {
        LOG.info("##### gotoLogoutPage logoutParam has been sent #####");
        paramHttpServletResponse.sendRedirect("/bdd/logoutB.jsf");
      } else if (str.contains("bdd")) {
        LOG.info("Context Path Contains bdd");
        paramHttpServletResponse.sendRedirect("/e360/mdm/entity360view/");
      } else {
        String str1 = (paramHttpServletRequest.getHeader("axa_mail") != null) ? paramHttpServletRequest.getHeader("axa_mail") : "";
        LOG.info("##### External login for " + str1 + " #####");
      } 
    } catch (Exception exception) {
      LOG.info("Exception in redirection. " + exception.getMessage());
      exception.printStackTrace();
    } 
    LOG.info("redirectToProviderLoginPage-----------Execution complete");
  }
  
  public LoginCredentials extractLoginCredentials(HttpServletRequest paramHttpServletRequest) throws LoginProviderException {
    LOG.info("extractLoginCredentials-----------Executing " + Thread.currentThread().getName());
    String str1 = (paramHttpServletRequest.getContextPath() != null) ? paramHttpServletRequest.getContextPath() : "";
    LOG.info("PATH : " + str1);
    HttpSession httpSession = paramHttpServletRequest.getSession();
    httpSession.setAttribute("extractLoginCredentialsCalled", "Y");
    LOG.info("request.getParameter(backDoor) : " + paramHttpServletRequest.getParameter("backDoor"));
    LoginCredentials loginCredentials = null;
    String str2 = null;
    if ("Y".equals(paramHttpServletRequest.getParameter("backDoor"))) {
      LOG.info("request.getParameter(username) : " + paramHttpServletRequest.getParameter("username"));
      LOG.info("request.getParameter(password) : " + paramHttpServletRequest.getParameter("password"));
      String str3 = "";
      String str4 = "";
      if (paramHttpServletRequest.getParameter("username") != null)
        str3 = paramHttpServletRequest.getParameter("username"); 
      if (paramHttpServletRequest.getParameter("password") != null)
        str4 = paramHttpServletRequest.getParameter("password"); 
      httpSession.setAttribute("iddUser", str3);
      str2 = str3;
      LOG.info("##### Back Door User Name : " + str3 + " #####");
      loginCredentials = new LoginCredentials(str3, str4);
    } else {
      LOG.info("request.getHeader(sm_timetoexpire) : " + paramHttpServletRequest.getHeader("sm_timetoexpire") + " seconds #####");
      if (paramHttpServletRequest.getHeader("axa_mail") != null)
        str2 = paramHttpServletRequest.getHeader("axa_mail").trim(); 
      LOG.info("DEBUG : email " + str2);
      if (str2 == null) {
        LOG.info("extractLoginCredentials----Email is NULL.");
        loginCredentials = null;
      } else {
        LOG.info("Attempting to Login : " + str2);
        httpSession.setAttribute("iddUser", str2);
        String str = str2.split("@")[0];
        LOG.info("Email  : " + str2);
        LOG.info("Password : " + str);
        loginCredentials = new LoginCredentials(str2, str);
      } 
    } 
    if (loginCredentials != null) {
      LOG.info("##### Hub authentication success for " + str2 + " @ " + DEFAULT_DATE_FMT.format(new Date()) + " #####");
    } else {
      LOG.info("##### Hub authentication fail for " + str2 + " @ " + DEFAULT_DATE_FMT.format(new Date()) + " #####");
    } 
    LOG.info("extractLoginCredentials-----------Execution end.");
    return loginCredentials;
  }
  
  public LoginCredentials requestLoginCredentials(String paramString1, String paramString2) throws LoginProviderException {
    LOG.info("requestLoginCredentials-------------------Called");
    return new LoginCredentials(paramString1, paramString2);
  }
  
  public String encodeComponentUrl(String paramString) throws LoginProviderException {
    LOG.info("encodeComponentUrl----------------------Called");
    return null;
  }
  
  public void onLogout(HttpServletRequest paramHttpServletRequest, HttpServletResponse paramHttpServletResponse) {
    LOG.info("onLogout---------------------Executing " + Thread.currentThread().getName());
    String str1 = (paramHttpServletRequest.getContextPath() != null) ? paramHttpServletRequest.getContextPath() : "";
    LOG.info("PATH : " + str1);
    HttpSession httpSession = paramHttpServletRequest.getSession();
    httpSession.setAttribute("onLogoutCalled", "Y");
    String str2 = paramHttpServletRequest.getHeader("axa_mail");
    String str3 = (String)httpSession.getAttribute("iddUser");
    String str4 = null;
    Cookie[] arrayOfCookie = paramHttpServletRequest.getCookies();
    for (byte b = 0; b < arrayOfCookie.length; b++) {
      String str = arrayOfCookie[b].getName();
      if (str != null && "auth_hash_cookie".equals(str)) {
        str4 = arrayOfCookie[b].getValue();
        break;
      } 
    } 
    LOG.info("##### internalEmail : " + str3 + " | externalEmail : " + str2 + " | userEmail : " + str4 + " #####");
    try {
      if (!paramHttpServletResponse.isCommitted())
        try {
          LOG.info("##### Preparing to call LOGOUT_TARGET #####");
          paramHttpServletResponse.setContentType("application/json");
          paramHttpServletResponse.setHeader("Cache-Control", "no-cache, no-store");
          String str5 = "{\"kerberos\":\"true\", \"logoutURL\":\"%s\"}";
          String str6 = String.format(str5, new Object[] { "/mdm/entity360view/?logoutParam=gotoLogoutPage" });
          LOG.info("##### jsonStr Created #####");
          LOG.info("##### logoutURL:/mdm/entity360view/?logoutParam=gotoLogoutPage#####");
          paramHttpServletResponse.getOutputStream().write(str6.getBytes());
          paramHttpServletResponse.getOutputStream().flush();
        } catch (Exception exception) {
          LOG.error("Error sending redirect in onLogout. ", exception.getMessage());
          exception.printStackTrace();
        }  
    } catch (LinkageError linkageError) {
      LOG.error("onLogout called from old IDD. Linkage Error handled. ", linkageError.getMessage());
    } 
    LOG.info("onLogout---------------------Execution completed");
  }
  
  public InputStream getLogoImageBody() {
    LOG.info("##### getLogoImageBody() #####");
    return null;
  }
  
  public void initialize(Properties paramProperties) {
    LOG.info("##### initialize : v2.2 #####");
  }
  
  public boolean isUseIDDLoginForm() {
    return false;
  }
}


/* Location:              /Users/a734ez/dev/mdmsso/SSOLoginProvider/!/com/axa/sso/SSOLoginProvider.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       1.1.3
 */