package burp.Application.ShiroFingerprintExtension.ExtensionMethod;

import burp.*;
import burp.Application.ShiroFingerprintExtension.ExtensionInterface.AShiroFingerprintExtension;
import burp.Bootstrap.YamlReader;

import java.io.PrintWriter;
import java.net.URL;
import java.util.List;

public class ShiroFingerprint3 extends AShiroFingerprintExtension {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private YamlReader yamlReader;
    private IHttpRequestResponse baseRequestResponse;

    private String rememberMeCookieName = "rememberMe";
    private String rememberMeCookieValue = "3";

    public ShiroFingerprint3(IBurpExtenderCallbacks callbacks, YamlReader yamlReader, IHttpRequestResponse baseRequestResponse) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.yamlReader = yamlReader;
        this.baseRequestResponse = baseRequestResponse;
        this.setExtensionName("ShiroFingerprint3");

        this.runConditionCheck();

    }

    private void runConditionCheck() {
        List<IParameter> parameters = this.helpers.analyzeRequest(this.baseRequestResponse).getParameters();
        for (IParameter parameter : parameters) {
            if (parameter.getType() != 2){
                continue;
            }
            if (parameter.getName() != this.rememberMeCookieName){
                continue;
            }
            if (parameter.getValue() == null ||parameter.getValue().length() == 0){
                continue;
            }

            this.rememberMeCookieValue = parameter.getValue();

            List<ICookie> cookies = this.helpers.analyzeResponse(this.baseRequestResponse.getResponse()).getCookies();
            for (ICookie cookie : cookies) {
                if (cookie.getName().equals(this.rememberMeCookieName) && cookie.getValue().equals("deleteMe")){
                    this.registerExtension();
                    return;
                }
            }

        }
    }

    public void RunExtension() {
        this.setHttpRequestResponse(baseRequestResponse);

        for (ICookie cookie : this.helpers.analyzeResponse(this.baseRequestResponse.getResponse()).getCookies()) {
            if (cookie.getName().equals(this.rememberMeCookieName)) {
                if (cookie.getValue().equals("deleteMe")) {
                    this.setShiroFingerprint();

                    this.setRequestDefaultRememberMeCookieName(this.rememberMeCookieName);
                    this.setRequestDefaultRememberMeCookieValue(this.rememberMeCookieValue);

                    this.setResponseDefaultRememberMeCookieName(cookie.getName());
                    this.setResponseDefaultRememberMeCookieValue(cookie.getValue());
                    break;
                }
            }
        }
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
        String str3 = String.format("[+] The request packet contains RememberMe, so no new request will be sent<br/>");
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
