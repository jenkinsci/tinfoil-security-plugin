package com.tinfoilsecurity.apiscanner.api;

public class Scan {
  private int id;
  private boolean running;

  public Scan(int id, boolean running) {
    this.id = id;
    this.running = running;
  }

  public int getScanID() {
    return id;
  }

  public boolean isRunning() {
    return running;
  }
}
