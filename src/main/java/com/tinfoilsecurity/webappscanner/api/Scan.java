package com.tinfoilsecurity.webappscanner.api;

public class Scan {
  private String id;

  public Scan(String id) {
    this.id = id;
  }

  public String getScanID() {
    return id;
  }
}
