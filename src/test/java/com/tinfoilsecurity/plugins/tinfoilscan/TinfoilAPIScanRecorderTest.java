package com.tinfoilsecurity.plugins.tinfoilscan;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Matchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.concurrent.ExecutionException;

import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl;
import com.tinfoilsecurity.apiscanner.api.Client;
import com.tinfoilsecurity.apiscanner.api.Client.APIException;
import com.tinfoilsecurity.apiscanner.api.Scan;

import hudson.EnvVars;
import hudson.model.FreeStyleBuild;
import hudson.model.FreeStyleProject;
import hudson.model.Item;

public class TinfoilAPIScanRecorderTest {
  @Rule
  public JenkinsRule j = new JenkinsRule();

  @Test
  public void shouldReportSuccessOnSuccessfulScan() throws Exception {
    FreeStyleBuild b = buildWhereTinfoilReturns(new Scan(12, true));
    j.assertLogContains("Tinfoil Security API scan started!", b);
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

    StandardUsernamePasswordCredentials credentials = new UsernamePasswordCredentialsImpl(CredentialsScope.SYSTEM, null,
        "", "foo", "bar");

    // We need tinfoil.getDescriptor().buildClient() to return a mock, so we need to
    // create
    // the mock and stub out two methods.
    TinfoilAPIScanRecorder tinfoil = new TinfoilAPIScanRecorder(credentials.getId(), null, siteID, null, null);

    Client client = mock(Client.class);
    when(client.startScan(siteID)).thenThrow(t);

    TinfoilAPIScanRecorder.DescriptorImpl descriptorSpy = spy(tinfoil.getDescriptor());
    when(descriptorSpy.buildClient(any(EnvVars.class), eq("foo"), eq("bar"), isNull(String.class), isNull(String.class),
        isNull(Integer.class))).thenReturn(client);

    tinfoil = spy(tinfoil);
    when(tinfoil.resolveCredential(any(Item.class), eq(credentials.getId()))).thenReturn(credentials);
    when(tinfoil.getDescriptor()).thenReturn(descriptorSpy);
    p.getPublishersList().add(tinfoil);
    return p.scheduleBuild2(0).get();
  }

  private FreeStyleBuild buildWhereTinfoilReturns(Scan s)
      throws IOException, APIException, InterruptedException, ExecutionException {
    FreeStyleProject p = j.createFreeStyleProject();
    String siteID = "test-site";

    StandardUsernamePasswordCredentials credentials = new UsernamePasswordCredentialsImpl(CredentialsScope.SYSTEM, null,
        "", "foo", "bar");

    // We need tinfoil.getDescriptor().buildClient() to return a mock, so we need to
    // create
    // the mock and stub out two methods.
    TinfoilAPIScanRecorder tinfoil = new TinfoilAPIScanRecorder(credentials.getId(), null, siteID, null, null);

    Client client = mock(Client.class);
    when(client.startScan(siteID)).thenReturn(s);

    TinfoilAPIScanRecorder.DescriptorImpl descriptorSpy = spy(tinfoil.getDescriptor());
    when(descriptorSpy.buildClient(any(EnvVars.class), eq("foo"), eq("bar"), isNull(String.class), isNull(String.class),
        isNull(Integer.class))).thenReturn(client);

    tinfoil = spy(tinfoil);
    when(tinfoil.resolveCredential(any(Item.class), eq(credentials.getId()))).thenReturn(credentials);
    when(tinfoil.getDescriptor()).thenReturn(descriptorSpy);
    p.getPublishersList().add(tinfoil);
    return p.scheduleBuild2(0).get();
  }
}
