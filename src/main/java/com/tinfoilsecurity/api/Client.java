package com.tinfoilsecurity.api;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.json.JSONArray;
import org.json.JSONObject;

import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;
import com.tinfoilsecurity.api.Report.Classification;

public class Client {
  public static class APIException extends Exception {

    private static final String DEFAULT_MESSAGE = "An unexpected error has occured. Perhaps the Tinfoil API is down.";

    public APIException() {
      super(DEFAULT_MESSAGE);
    }

    public APIException(String message) {
      super(message);
    }
  };

  public static final String DEFAULT_API_HOST = "https://www.tinfoilsecurity.com";
  
  private String apiHost = DEFAULT_API_HOST;

  private static final String ENDPOINT_START_SCAN = "/api/v1/sites/{site_id}/scans";
  private static final String ENDPOINT_GET_SCANS  = "/api/v1/sites/{site_id}/scans";
  private static final String ENDPOINT_GET_REPORT = "/api/v1/sites/{site_id}/scans/{scan_id}/report";

  public Client(String accessKey, String secretKey) {
    Unirest.setDefaultHeader("Authorization", "Token token=" + secretKey + ", access_key=" + accessKey);
  }

  public void setAPIHost(String host) {
    this.apiHost = host;
  }

  public Scan startScan(String siteID) throws APIException {
    HttpResponse<JsonNode> res = null;
    try {
      res = Unirest.post(apiHost + ENDPOINT_START_SCAN).routeParam("site_id", siteID).asJson();
    }
    catch (UnirestException e) {
      throw new APIException();
    }

    switch (res.getStatus()) {
    case 201:
      return scanFromJSON(res.getBody().getObject());
    case 401:
      throw new APIException("Your API credentials are invalid.");
    case 404:
      throw new APIException("A site could not be found with the given Site ID: " + siteID + ".");
    case 409:
      throw new APIException("A scan is already running on this site.");
    case 412:
      throw new APIException(
          "Your site has possible configuration errors. Please log in to Tinfoil Security to review them.");
    default:
      throw new APIException();
    }
  }

  public boolean isScanRunning(String siteID, String scanID) throws APIException {
    Map<String, Object> params = Collections.unmodifiableMap(new HashMap<String, Object>() {
      {
        put("page", 1);
        put("per_page", 1);
        put("status", "running");
      }
    });

    HttpResponse<JsonNode> res;

    try {
      res = Unirest.get(apiHost + ENDPOINT_GET_SCANS).routeParam("site_id", siteID).queryString(params).asJson();
    }
    catch (UnirestException e) {
      throw new APIException();
    }

    switch (res.getStatus()) {
    case 200:
      JSONArray scans = res.getBody().getObject().getJSONArray("scans");
      if (scans.length() > 0) {
        return scanID.equals(scans.getJSONObject(0).getString("id"));
      }
      else {
        return false;
      }
    case 404:
      throw new APIException("A site could not be found with the given Site ID: " + siteID + ".");

    default:
      throw new APIException();
    }
  }

  public Report getReport(String siteID, String scanID) throws APIException {
    Map<String, Object> params = Collections.unmodifiableMap(new HashMap<String, Object>() {
      {
        put("page", 1);
        put("per_page", 1);
      }
    });

    HttpResponse<JsonNode> res;

    try {
      res = Unirest.get(apiHost + ENDPOINT_GET_REPORT).routeParam("site_id", siteID).routeParam("scan_id", scanID)
          .queryString(params).asJson();
    }
    catch (UnirestException e) {
      throw new APIException();
    }

    switch (res.getStatus()) {
    case 200:
      return reportFromJSON(res.getBody().getObject());
    case 404:
      throw new APIException("This report could not be found.");
    default:
      throw new APIException();
    }
  }

  public void close() {
    Unirest.clearDefaultHeaders();
    try {
      Unirest.shutdown();
    }
    catch (IOException e) {}
  }

  private static Scan scanFromJSON(JSONObject object) {
    String scanID = object.getJSONObject("scan").getString("id");
    return new Scan(scanID);
  }

  private static Report reportFromJSON(JSONObject object) {
    return new Report(Classification.fromString(object.getString("classification")));
  }
}
