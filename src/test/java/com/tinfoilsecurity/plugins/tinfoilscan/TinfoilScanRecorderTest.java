package com.tinfoilsecurity.plugins.tinfoilscan;

import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import static org.mockito.Mockito.*;

import java.io.IOException;
import java.util.concurrent.ExecutionException;

import com.tinfoilsecurity.api.Client;
import com.tinfoilsecurity.api.Client.APIException;
import com.tinfoilsecurity.api.Scan;

import hudson.model.FreeStyleBuild;
import hudson.model.FreeStyleProject;

public class TinfoilScanRecorderTest {
  @Rule
  public JenkinsRule j = new JenkinsRule();

  @Test
  public void shouldReportSuccessOnSuccessfulScan() throws Exception {
    FreeStyleBuild b = buildWhereTinfoilReturns(new Scan("test-site"));
    j.assertLogContains("Tinfoil Security scan started!", b);
  }

  @Test
  public void shouldReportAPIIssuesWhenErrorIsThrown() throws Exception {
    String testString = "Something went seriously, horribly wrong.";
    FreeStyleBuild b = buildWhereTinfoilThrows(new APIException(testString));
    j.assertLogContains(testString, b);
  }

  private FreeStyleBuild buildWhereTinfoilThrows(Throwable t)
      throws IOException, APIException, InterruptedException, ExecutionException {
    FreeStyleProject p = j.createFreeStyleProject();
    String siteID = "test-site";

    // We need tinfoil.getDescriptor().buildClient() to return a mock, so we need to create
    // the mock and stub out two methods.
    TinfoilScanRecorder tinfoil = new TinfoilScanRecorder(siteID);

    Client client = mock(Client.class);
    when(client.startScan(siteID)).thenThrow(t);

    TinfoilScanRecorder.DescriptorImpl descriptorSpy = spy(tinfoil.getDescriptor());
    when(descriptorSpy.buildClient()).thenReturn(client);

    tinfoil = spy(tinfoil);
    when(tinfoil.getDescriptor()).thenReturn(descriptorSpy);
    p.getPublishersList().add(tinfoil);
    return p.scheduleBuild2(0).get();
  }

  private FreeStyleBuild buildWhereTinfoilReturns(Scan s)
      throws IOException, APIException, InterruptedException, ExecutionException {
    FreeStyleProject p = j.createFreeStyleProject();
    String siteID = "test-site";

    // We need tinfoil.getDescriptor().buildClient() to return a mock, so we need to create
    // the mock and stub out two methods.
    TinfoilScanRecorder tinfoil = new TinfoilScanRecorder(siteID);

    Client client = mock(Client.class);
    when(client.startScan(siteID)).thenReturn(s);

    TinfoilScanRecorder.DescriptorImpl descriptorSpy = spy(tinfoil.getDescriptor());
    when(descriptorSpy.buildClient()).thenReturn(client);

    tinfoil = spy(tinfoil);
    when(tinfoil.getDescriptor()).thenReturn(descriptorSpy);
    p.getPublishersList().add(tinfoil);
    return p.scheduleBuild2(0).get();
  }
}
