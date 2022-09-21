package burp.Application.ShiroFingerprintExtension.ExtensionMethod;

import burp.*;
import burp.Application.ShiroFingerprintExtension.ExtensionInterface.AShiroFingerprintExtension;
import burp.Bootstrap.YamlReader;

import java.io.PrintWriter;
import java.net.URL;

public class ShiroFingerprint2 extends AShiroFingerprintExtension {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private YamlReader yamlReader;
    private IHttpRequestResponse baseRequestResponse;

    private String rememberMeCookieValue = "2";

    public ShiroFingerprint2(IBurpExtenderCallbacks callbacks, YamlReader yamlReader, IHttpRequestResponse baseRequestResponse) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.yamlReader = yamlReader;
        this.baseRequestResponse = baseRequestResponse;

        this.setExtensionName("ShiroFingerprint2");

        this.runConditionCheck();
    }

    private void runConditionCheck() {
        for (ICookie cookie : this.helpers.analyzeResponse(baseRequestResponse.getResponse()).getCookies()) {
            if (cookie.getValue().equals("deleteMe")){
                this.registerExtension();
                break;
            }
        }
    }

    public void RunExtension() {
        if (!this.isRunExtension()) {
            return;
        }

        // 先保存一个基础的请求响应
        this.setHttpRequestResponse(this.baseRequestResponse);

        for (ICookie c : this.helpers.analyzeResponse(this.baseRequestResponse.getResponse()).getCookies()) {
            if (c.getValue().equals("deleteMe")) {
                this.setShiroFingerprint();

                // 二次确认过的请求响应, 可以获得最真实的结果
                IHttpRequestResponse newHttpRequestResponse = this.getNewHttpRequestResponse(
                        c.getName(),
                        this.rememberMeCookieValue);

                // 二次确认的请求确定是shiro框架了
                // 保存这个最真实的结果, 覆盖上面那个基础的请求响应
                this.setHttpRequestResponse(newHttpRequestResponse);

                this.setRequestDefaultRememberMeCookieName(c.getName());
                this.setRequestDefaultRememberMeCookieValue(this.rememberMeCookieValue);

                this.setResponseDefaultRememberMeCookieName(c.getName());
                this.setResponseDefaultRememberMeCookieValue(c.getValue());
                break;
            }
        }
    }

    private IHttpRequestResponse getNewHttpRequestResponse(String rememberMeCookieName, String rememberMeCookieValue) {
        IParameter newParameter = this.helpers.buildParameter(rememberMeCookieName, rememberMeCookieValue, (byte) 2);
        byte[] newRequest = this.helpers.updateParameter(this.baseRequestResponse.getRequest(), newParameter);

        IHttpService httpService = this.baseRequestResponse.getHttpService();

        IHttpRequestResponse newHttpRequestResponse = this.callbacks.makeHttpRequest(httpService, newRequest);

        return newHttpRequestResponse;

    }

    @Override
    public IScanIssue export() {
        if (!this.isRunExtension()){
            return null;
        }

        if (!this.isShiroFingerprint()){
            return null;
        }

        String str1 = String.format("============ShiroFinger_Detail============<br/>");
        String str2 = String.format("ExtensionMethod: %s <br/>", this.getExtensionName());
        String str3 = String.format("[+] The response package contains deleteMe and sends a second request for confirmation<br/>");
        String str4 = String.format("RequestCookiePayload: rememberMe=%s <br/>", this.getRequestDefaultRememberMeCookieValue());
        String str5 = String.format("ResponseReturnCookie: rememberMe=%s <br/>", this.getResponseDefaultRememberMeCookieValue());
        String str6 = String.format("==========================================<br/>");

        String detail = str1 + str2 + str3 + str4 + str5 + str6;

        URL url = this.helpers.analyzeRequest(baseRequestResponse).getUrl();
        String issueName = this.yamlReader.getString("webSite.shiroFrameDetection.config.issueName");
        IHttpRequestResponse baseHttpRequestResponse = this.getHttpRequestResponse();
        return new CustomScanIssue(
                url,
                issueName,
                0,
                "Information",
                "Certain",
                null,
                null,
                detail,
                null,
                new IHttpRequestResponse[]{baseHttpRequestResponse},
                baseHttpRequestResponse.getHttpService()
        );
    }

    @Override
    public void consoleExport() {
        if (!this.isRunExtension()) {
            return;
        }

        if (!this.isShiroFingerprint()) {
            return;
        }

        IHttpRequestResponse baseHttpRequestResponse = this.getHttpRequestResponse();
        PrintWriter stdout = new PrintWriter(this.callbacks.getStdout(), true);

        stdout.println("");
        stdout.println("============检测到shiro指纹============");
        stdout.println("检测扩展: " + this.getExtensionName());
        stdout.println("HOST: " + baseHttpRequestResponse.getHttpService().getHost());
        stdout.println("URL: " + this.helpers.analyzeRequest(baseHttpRequestResponse).getUrl().toString());
        stdout.println(String.format("请求cookie: %s=%s" ,this.getRequestDefaultRememberMeCookieName(), this.getResponseDefaultRememberMeCookieValue()));
        stdout.println(String.format("响应cookie: %s=%s" ,this.getResponseDefaultRememberMeCookieName(), this.getResponseDefaultRememberMeCookieValue()));
        stdout.println("详情请查看-Target/Dashboard模块-Issue界面");
        stdout.println("=====================================");
        stdout.println("");
    }
}
