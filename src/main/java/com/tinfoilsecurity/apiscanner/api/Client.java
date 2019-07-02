package com.tinfoilsecurity.apiscanner.api;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;

import javax.net.ssl.SSLContext;

import org.apache.http.HttpHost;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLContexts;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.json.JSONObject;

import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;

public class Client {
  public static class APIException extends Exception {
    private static final long serialVersionUID = 1L;

    public APIException() {
      super(DEFAULT_MESSAGE);
    }

    public APIException(String message) {
      super(message);
    }
  };

  public static final String DEFAULT_API_HOST = "https://api-scanner.tinfoilsecurity.com";
  private static final String DEFAULT_MESSAGE = "An unexpected error has occured. Perhaps the Tinfoil API is down.";
  private static final String ENDPOINT_START_SCAN = "/api/v1/apis/{api_id}/scans";
  private static final String ENDPOINT_GET_SCAN = "/api/v1/scans/{scan_id}";
  private String apiHost = DEFAULT_API_HOST;
  private HttpClientBuilder httpClientBuilder;

  public Client(String accessKey, String secretKey) {
    this.httpClientBuilder = HttpClients.custom().useSystemProperties();

    Unirest.setDefaultHeader("Authorization", "Token token=" + secretKey + ", access_key=" + accessKey);
  }

  public void setAPIHost(String host) {
    this.apiHost = host;

    trustAllCerts();
  }

  public void setProxyConfig(String proxyHost, Integer proxyPort) {
    HttpHost httpHost = new HttpHost(proxyHost, proxyPort);
    CloseableHttpClient client = this.httpClientBuilder.setProxy(httpHost).build();
    Unirest.setHttpClient(client);
  }

  public Scan startScan(String apiID) throws APIException {
    HttpResponse<JsonNode> res = null;
    try {
      res = Unirest.post(apiHost + ENDPOINT_START_SCAN).routeParam("api_id", apiID).asJson();
    } catch (UnirestException e) {
      throw new APIException(e.getMessage());
    }

    switch (res.getStatus()) {
    case 200:
      return scanFromJSON(res.getBody().getObject());
    case 401:
      throw new APIException("Your API credentials are invalid.");
    case 404:
      throw new APIException("An API could not be found with the given ID: " + apiID + ".");
    case 409:
      throw new APIException("A scan is already running on this API.");
    case 422:
      throw new APIException(
          "Your API has possible configuration errors. Please log in to the Tinfoil Security API Scanner to review them.");
    case 500:
      throw new APIException("An error occured on the Tinfoil application. Please try again later.");
    default:
      throw new APIException();
    }
  }

  public boolean isScanRunning(String scanID) throws APIException {
    HttpResponse<JsonNode> res;

    try {
      res = Unirest.get(apiHost + ENDPOINT_GET_SCAN).routeParam("scan_id", scanID).asJson();
    } catch (UnirestException e) {
      throw new APIException();
    }

    switch (res.getStatus()) {
    case 200:
      Scan scan = scanFromJSON(res.getBody().getObject());
      return scan.isRunning();
    case 404:
      throw new APIException("A scan could not be found with the given ID: " + scanID + ".");

    default:
      throw new APIException();
    }
  }

  public Report getReport(String scanID) throws APIException {
    throw new RuntimeException("Not implemented yet.");
  }

  public void close() {
    Unirest.clearDefaultHeaders();
    try {
      Unirest.shutdown();
    } catch (IOException e) {
    }
  }

  private void trustAllCerts() {
    SSLContext sslcontext = null;
    try {
      sslcontext = SSLContexts.custom().loadTrustMaterial(null, new TrustSelfSignedStrategy()).build();
    } catch (KeyManagementException e) {
      e.printStackTrace();
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    } catch (KeyStoreException e) {
      e.printStackTrace();
    }

    SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslcontext,
        SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
    CloseableHttpClient httpclient = this.httpClientBuilder.setSSLSocketFactory(sslsf).build();

    Unirest.setHttpClient(httpclient);
  }

  private static Scan scanFromJSON(JSONObject object) {
    int scanID = object.getInt("id");
    boolean running = object.get("finished_at") == null;
    return new Scan(scanID, running);
  }
}
