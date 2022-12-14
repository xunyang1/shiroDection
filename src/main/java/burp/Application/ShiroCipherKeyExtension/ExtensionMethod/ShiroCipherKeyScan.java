package burp.Application.ShiroCipherKeyExtension.ExtensionMethod;

import burp.*;
import burp.Application.ShiroCipherKeyExtension.ExtensionInterface.AShiroCipherKeyExtension;
import burp.Application.ShiroFingerprintExtension.ShiroFingerprint;
import burp.Bootstrap.*;
import burp.Bootstrap.Encrypt.EncryptInterface;
import burp.CustomErrorException.TaskTimeoutException;
import org.apache.shiro.subject.SimplePrincipalCollection;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.URL;
import java.util.Date;
import java.util.List;

public class ShiroCipherKeyScan extends AShiroCipherKeyExtension {
    private GlobalVariableReader globalVariableReader;
    private GlobalPassiveScanVariableReader globalPassiveScanVariableReader;

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;

    private YamlReader yamlReader;

    private IHttpRequestResponse baseRequestResponse;

    private ShiroFingerprint shiroFingerprint;

    private List<String> payloads;

    private EncryptInterface encryptClass;

    private Date startDate;

    private Integer maxExecutionTime;

    private CustomBurpHelpers customBurpHelpers;

    private IHttpRequestResponse shiroFingerprintHttpRequestResponse;

    private String rememberMeCookieName;

    private String responseRememberMeCookieValue;

    private String newRequestRememberMeCookieValue;

    public ShiroCipherKeyScan(GlobalVariableReader globalVariableReader,
                              GlobalPassiveScanVariableReader globalPassiveScanVariableReader,
                              IBurpExtenderCallbacks callbacks,
                              YamlReader yamlReader,
                              IHttpRequestResponse baseRequestResponse,
                              ShiroFingerprint shiroFingerprint,
                              List<String> payloads,
                              EncryptInterface encryptClass,
                              Date startDate,
                              Integer maxExecutionTime) throws IOException {
        this.globalVariableReader = globalVariableReader;
        this.globalPassiveScanVariableReader = globalPassiveScanVariableReader;

        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);

        this.yamlReader = yamlReader;
        this.baseRequestResponse = baseRequestResponse;
        this.shiroFingerprint = shiroFingerprint;
        this.payloads = payloads;
        this.encryptClass = encryptClass;
        this.startDate = startDate;
        this.maxExecutionTime = maxExecutionTime;

        this.customBurpHelpers = new CustomBurpHelpers(this.callbacks);


        this.shiroFingerprintHttpRequestResponse = this.shiroFingerprint.getShiroFingerprint().getHttpRequestResponse();

        this.rememberMeCookieName = this.shiroFingerprint.getShiroFingerprint().getResponseDefaultRememberMeCookieName();
        this.responseRememberMeCookieValue = this.shiroFingerprint.getShiroFingerprint().getResponseDefaultRememberMeCookieValue();
        this.newRequestRememberMeCookieValue = "";

        this.setExtensionName("ShiroCipherKeyScan");

        this.runExtension();
    }

    private void runExtension() throws IOException {
        if (this.payloads.size() <= 0) {
            throw new IllegalArgumentException("shiro??????key????????????-??????????????????payloads????????????, ?????????");
        }
        byte[] exp = this.encryptClass.getBytes(new SimplePrincipalCollection());

        for (String key : this.payloads) {
            // ???????????????true???????????????????????????,??????????????????,??????????????????
            if (this.globalVariableReader.getBooleanData("isExtensionUnload")) {
                return;
            }

            // ?????????????????????????????????shiro key???,???????????????????????????
            if (this.globalPassiveScanVariableReader.getBooleanData("isEndShiroCipherKeyTask")) {
                return;
            }
            // ???????????????shiro key???
            if (this.isShiroCipherKeyExists()) {
                return;
            }

            // ??????????????????????????????
            int startTime = CustomHelpers.getSecondTimestamp(this.startDate);
            int currentTime = CustomHelpers.getSecondTimestamp(new Date());
            int runTime = currentTime - startTime;
            if (runTime >= this.maxExecutionTime) {
                throw new TaskTimeoutException("shiro key scan task timeout");
            }

            this.cipherKeyDetection(key, exp);
        }

    }

    private void cipherKeyDetection(String key, byte[] exp) {
        String correctRememberMe = this.encryptClass.encrypt(key, exp);
        IHttpRequestResponse newHttpRequestResponse1 = this.getNewHttpRequestResponse(correctRememberMe);

        if (key.equals("kPH+bIxk5D2deZiIxcaaaA==")){
            System.out.println(key);
        }

        int newHttpCookieRememberMeNumber = this.getHttpCookieRememberMeNumber(newHttpRequestResponse1);

        if (newHttpCookieRememberMeNumber != 0){
            return;
        }

        //??????RememberMe????????????0????????????????????????
        this.setIssuesDetail(newHttpRequestResponse1, key, this.encryptClass.getName(), correctRememberMe);
    }

    private void setIssuesDetail(IHttpRequestResponse newHttpRequestResponse1, String key, String encryptMethod, String correctRememberMe) {
        this.setShiroCipherKeyExists();
        this.setCipherKey(key);
        this.setEncryptMethod(encryptMethod);
        this.setHttpRequestResponse(newHttpRequestResponse1);
        this.setNewRequestRememberMeCookieValue(correctRememberMe);
    }

    private void setNewRequestRememberMeCookieValue(String value) {
        this.newRequestRememberMeCookieValue = value;
    }

    private String getNewRequestRememberMeCookieValue() {
        return this.newRequestRememberMeCookieValue;
    }

    /**
     * ??????http cookie ????????????????????????
     *
     * @param httpRequestResponse
     * @return
     */
    private int getHttpCookieRememberMeNumber(IHttpRequestResponse httpRequestResponse) {
        int number = 0;
        for (ICookie c : this.helpers.analyzeResponse(httpRequestResponse.getResponse()).getCookies()) {
            if (c.getName().equals(this.rememberMeCookieName)) {
                if (c.getValue().equals(this.responseRememberMeCookieValue) || c.getValue().equals("deleteMe")) {
                    number++;
                }
            }
        }
        return number;
    }

    private IHttpRequestResponse getNewHttpRequestResponse(String correctRememberMe) {
        IHttpService httpService = this.baseRequestResponse.getHttpService();
        IParameter newParameter = this.helpers.buildParameter(this.rememberMeCookieName, correctRememberMe, (byte) 2);

        byte[] newRequest = this.helpers.updateParameter(this.baseRequestResponse.getRequest(), newParameter);

        IHttpRequestResponse newHttpRequestResponse = this.callbacks.makeHttpRequest(httpService, newRequest);

        return newHttpRequestResponse;
    }

    @Override
    public IScanIssue export() {
        if (!this.isShiroCipherKeyExists()) {
            return null;
        }

        IHttpRequestResponse newHttpRequestResponse = this.getHttpRequestResponse();
        URL newHttpRequestUrl = this.helpers.analyzeRequest(newHttpRequestResponse).getUrl();

        String str1 = String.format("<br/>=============ShiroCipherKeyDetail============<br/>");
        String str2 = String.format("ExtensionMethod: %s <br/>", this.getExtensionName());
        String str3 = String.format("EncryptMethod: %s <br/>", this.encryptClass.getName());
        String str4 = String.format("CookieName: %s <br/>", this.rememberMeCookieName);
        String str5 = String.format("CookieValue: %s <br/>", this.getNewRequestRememberMeCookieValue());
        String str6 = String.format("ShiroCipherKey: %s <br/>", this.getCipherKey());
        String str7 = String.format("=====================================<br/>");

        String detail = str1 + str2 + str3 + str4 + str5 + str6 + str7;

        String shiroCipherKeyIssueName = this.yamlReader.getString("webSite.shiroCipherKeyDetection.config.issueName");

        return new CustomScanIssue(
                newHttpRequestUrl,
                shiroCipherKeyIssueName,
                0,
                "High",
                "Certain",
                null,
                null,
                detail,
                null,
                new IHttpRequestResponse[]{newHttpRequestResponse},
                newHttpRequestResponse.getHttpService()
        );
    }

    @Override
    public void consoleExport() {
        if (!this.isShiroCipherKeyExists()) {
            return;
        }

        IHttpRequestResponse newHttpRequestResponse = this.getHttpRequestResponse();
        URL newHttpRequestUrl = this.helpers.analyzeRequest(newHttpRequestResponse).getUrl();
        String newHttpRequestMethod = this.helpers.analyzeRequest(newHttpRequestResponse.getRequest()).getMethod();
        int newHttpResponseStatusCode = this.helpers.analyzeResponse(newHttpRequestResponse.getResponse()).getStatusCode();

        this.stdout.println("");
        this.stdout.println("===========shiro??????key??????============");
        this.stdout.println(String.format("?????????????????????: %s", this.getExtensionName()));
        this.stdout.println(String.format("?????????????????????: %s", this.encryptClass.getName()));
        this.stdout.println(String.format("url: %s", newHttpRequestUrl));
        this.stdout.println(String.format("????????????: %s", newHttpRequestMethod));
        this.stdout.println(String.format("??????http??????: %d", newHttpResponseStatusCode));
        this.stdout.println(String.format("?????????Cookie???: %s", this.rememberMeCookieName));
        this.stdout.println(String.format("?????????Cookie???: %s", this.getNewRequestRememberMeCookieValue()));
        this.stdout.println(String.format("Shiro??????key: %s", this.getCipherKey()));
        this.stdout.println("???????????????-Target/Dashboard??????-Issue??????");
        this.stdout.println("===================================");
        this.stdout.println("");
    }
}
