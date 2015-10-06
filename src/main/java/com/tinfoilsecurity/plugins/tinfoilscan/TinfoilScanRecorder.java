package com.tinfoilsecurity.plugins.tinfoilscan;

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

  private String siteID;

  // Fields in config.jelly must match the parameter names in the "DataBoundConstructor"
  @DataBoundConstructor
  public TinfoilScanRecorder(String siteID) {
    this.siteID = siteID;
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
    Client tinfoilAPI = getDescriptor().buildClient();

    try {
      tinfoilAPI.startScan(siteID);

      listener.getLogger().println(
          "Tinfoil Security scan started! Log in to " + getDescriptor().getAPIHost() + "/sites to view its progress.");
    }
    catch (APIException e) {
      listener.getLogger().println("Your Tinfoil Security scan could not be started. " + e.getMessage());
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

    // This gets called when you save global settings. See global.jelly.
    @Override
    public boolean configure(StaplerRequest req, JSONObject json) throws FormException {
      if (json.getBoolean("applianceEnabled") && !json.getString("apiHost").isEmpty()) {
        apiHost = json.getString("apiHost");
      }
      else {
        apiHost = null;
      }      
      apiAccessKey = json.getString("accessKey");
      apiSecretKey = json.getString("secretKey");
      save();

      return super.configure(req, json);
    }
    
    public String getAPIHost() {
      return apiHost;
    }
    
    public boolean isApplianceEnabled() {
      return apiHost != null && !apiHost.isEmpty();
    }

    public String getAPIAccessKey() {
      return apiAccessKey;
    }

    public String getAPISecretKey() {
      return apiSecretKey;
    }

    public Client buildClient() {
      Client client = new Client(apiAccessKey, apiSecretKey);
      if (isApplianceEnabled()) {
        client.setAPIHost(apiHost);
      }
      return client;
    }
  }
}
