package com.tinfoilsecurity.api;

public class Report {
  public enum Classification {
    SAFE("safe"),
    MOSTLY_SAFE("mostly_safe"),
    BORDERLINE("borderline"),
    UNSAFE("unsafe"),
    VERY_UNSAFE("very_unsafe");
    
    private String text;
    
    Classification(String text) {
      this.text = text;
    }
    
    public static Classification fromString(String text) {
      if (text != null) {
        for (Classification c : Classification.values()) {
          if (text.equalsIgnoreCase(c.text)) {
            return c;
          }
        }
      }
      return null;
    }
  }
  
  private Classification classification;
  
  public Report(Classification classification) {
    this.classification = classification;
  }
  
  public Classification getClassification() {
    return classification;
  }
}
