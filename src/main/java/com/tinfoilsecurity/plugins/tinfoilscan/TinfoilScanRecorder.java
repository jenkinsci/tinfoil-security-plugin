package com.tinfoilsecurity.plugins.tinfoilscan;

import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.StaplerRequest;

import com.tinfoilsecurity.api.Client;
import com.tinfoilsecurity.api.Client.APIException;

import hudson.Extension;
import hudson.Launcher;
import hudson.model.AbstractBuild;
import hudson.model.AbstractProject;
import hudson.model.BuildListener;
import hudson.model.Result;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.BuildStepMonitor;
import hudson.tasks.Publisher;
import hudson.tasks.Recorder;
import net.sf.json.JSONObject;

public class TinfoilScanRecorder extends Recorder {
  
  private String apiAccessKey;
  private String apiSecretKey;
  private String apiHost;
  private String siteID;

  // Fields in config.jelly must match the parameter names in the "DataBoundConstructor"
  @DataBoundConstructor
  public TinfoilScanRecorder(String accessKey, String secretKey, String apiHost, String siteID) {
    this.apiAccessKey = accessKey;
    this.apiSecretKey = secretKey;
    this.apiHost = apiHost;
    this.siteID = siteID;
  }
  
  public String getAPIAccessKey() {
    return apiAccessKey;
  }
  
  public String getAPISecretKey() {
    return apiSecretKey;
  }
  
  public String getAPIHost() {
    return apiHost;
  }

  public String getSiteID() {
    return siteID;
  }

  @Override
  public BuildStepMonitor getRequiredMonitorService() {
    return BuildStepMonitor.STEP;
  }

  @Override
  public boolean perform(AbstractBuild<?, ?> build, Launcher launcher, BuildListener listener) {
    Client tinfoilAPI = getDescriptor().buildClient(getAPIAccessKey(), getAPISecretKey(), getAPIHost());

    try {
      tinfoilAPI.startScan(siteID);
      
      String host = StringUtils.isNotBlank(getAPIHost()) ? getAPIHost() : getDescriptor().getAPIHost();

      listener.getLogger().println(
          "Tinfoil Security scan started! Log in to " + host + "/sites to view its progress.");
    }
    catch (APIException e) {
      listener.getLogger().println("Your Tinfoil Security scan could not be started. " + e.getMessage());
    }
    finally {
    	tinfoilAPI.close();
    }

    build.setResult(Result.SUCCESS);
    return true;
  }

  // Overridden for better type safety.
  @Override
  public DescriptorImpl getDescriptor() {
    return DESCRIPTOR;
  }

  @Extension
  public static final DescriptorImpl DESCRIPTOR = new DescriptorImpl();

  public static class DescriptorImpl extends BuildStepDescriptor<Publisher> {

    private String apiHost;
    private String apiAccessKey;
    private String apiSecretKey;

    public DescriptorImpl() {
      load();
    }

    @Override
    public boolean isApplicable(Class<? extends AbstractProject> jobType) {
      // Applicable for all job types.
      return true;
    }

    @Override
    public String getDisplayName() {
      return "Tinfoil Security";
    }

    public String getDefaultAPIHost() {
      return Client.DEFAULT_API_HOST;
    }

    // This gets called when you save global settings. See global.jelly.
    @Override
    public boolean configure(StaplerRequest req, JSONObject json) throws FormException {
      apiHost = json.getString("apiHost");
      if (StringUtils.isBlank(apiHost)) {
        apiHost = getDefaultAPIHost();
      }
      apiAccessKey = json.getString("accessKey");
      apiSecretKey = json.getString("secretKey");
      save();

      return super.configure(req, json);
    }
    
    public String getAPIHost() {
      return apiHost;
    }

    public String getAPIAccessKey() {
      return apiAccessKey;
    }

    public String getAPISecretKey() {
      return apiSecretKey;
    }

    public Client buildClient(String apiAccessKey, String apiSecretKey, String apiHost) {
      if (StringUtils.isBlank(apiAccessKey)) {
        apiAccessKey = getAPIAccessKey();
      }
      if (StringUtils.isBlank(apiSecretKey)) {
        apiSecretKey = getAPISecretKey();
      }

      Client client = new Client(apiAccessKey, apiSecretKey);
      
      if (StringUtils.isBlank(apiHost)) {
        apiHost = getAPIHost();
      }
      if (getDefaultAPIHost() != apiHost) {
        client.setAPIHost(apiHost);
      }
      
      return client;
    }
  }
}
