package burp;

import burp.Application.ShiroCipherKeyExtension.ExtensionInterface.IShiroCipherKeyExtension;
import burp.Application.ShiroCipherKeyExtension.ShiroCipherKeyThread;
import burp.Application.ShiroFingerprintExtension.ExtensionInterface.IShiroFingerprintExtension;
import burp.Application.ShiroFingerprintExtension.ShiroFingerprint;
import burp.Bootstrap.CustomBurpReq;
import burp.Bootstrap.GlobalPassiveScanVariableReader;
import burp.Bootstrap.GlobalVariableReader;
import burp.Bootstrap.YamlReader;
import burp.Ui.Tags;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

public class BurpExtender implements IBurpExtender, IScannerCheck, IExtensionStateListener{
    public static String NAME = "shiroDetect";

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private PrintWriter stdout;
    private PrintWriter stderr;

    private GlobalVariableReader globalVariableReader;

    private Tags tags;

    private YamlReader yamlReader;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);

        //定义一个全局变量存储器，用于程序运行期间变量实时修改与访问
        this.globalVariableReader = new GlobalVariableReader();

        // 是否卸载扩展
        // 用于卸载插件以后,把程序快速退出去,避免卡顿
        // true = 已被卸载, false = 未卸载
        this.globalVariableReader.putBooleanData("isExtensionUnload", false);

        //加载标签页
        this.tags = new Tags(callbacks, NAME);

        //加载配置文件
        this.yamlReader = YamlReader.getInstance(callbacks);


        callbacks.setExtensionName(NAME);
        callbacks.registerScannerCheck(this);
        callbacks.registerExtensionStateListener(this);


    }

    @Override
    public void extensionUnloaded() {
        this.globalVariableReader.putBooleanData("isExtensionUnload", true);
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse iHttpRequestResponse) {
        //是否开启插件
        if (!this.tags.getBaseSettingsTag().isExtensionStart()){
            return null;
        }

        //定义issue集合
        List<IScanIssue> issues = new ArrayList<IScanIssue>();

        //提取黑白名单
        List<String> blackList = this.yamlReader.getStringList("scan.domainName.blacklist");
        List<String> whiteList = this.yamlReader.getStringList("scan.domainName.whiteList");

        //请求解析-封装
        CustomBurpReq customBurpReq = new CustomBurpReq(callbacks, iHttpRequestResponse);

        //判断是否在黑名单
        if (isMatchDomainName(customBurpReq.getRequestHost(), blackList)){
            return null;
        }

        //判断是否在白名单
        if (whiteList != null && whiteList.size() != 0){
            if (!isMatchDomainName(customBurpReq.getRequestHost(), whiteList)){
                return null;
            }
        }

        //判断域名是否在后缀黑名单
        if (this.isUrlBlackListSuffix(customBurpReq)){
            return null;
        }

        //判断当前站点是否超出扫描数量，过多的扫描也无意义，这里设置的是0即无限次
        Integer siteMaxScan = this.yamlReader.getInteger("scan.siteMaxScan");
        if (siteMaxScan > 0){
            Integer siteSiteMapNumber = this.getSiteMapNumber(customBurpReq);
            if (siteSiteMapNumber > siteMaxScan) {
                this.tags.getScanQueueTag().add(
                        "",
                        "",
                        customBurpReq.getRequestMethod(),
                        customBurpReq.getRequestUrl().toString(),
                        String.valueOf(this.helpers.analyzeResponse(iHttpRequestResponse.getResponse()).getStatusCode()),
                        "[*] The site has exceeded the maximum scanning limit, which can be modified in the configuration",
                        iHttpRequestResponse
                );
                return null;
            }
        }

        //判断当前站点指纹识别次数是否超过最大限制
        Integer FramIssueMaxNumber = this.yamlReader.getInteger("webSite.shiroFrameDetection.config.issueMaxNumber");
        if (FramIssueMaxNumber > 0){
            String issueName = this.yamlReader.getString("webSite.shiroFrameDetection.config.issueName");
            Integer issueNumber = this.getIssueNumber(customBurpReq, issueName);

            if (issueNumber > FramIssueMaxNumber){
                this.tags.getScanQueueTag().add(
                        "",
                        "",
                        customBurpReq.getRequestMethod(),
                        customBurpReq.getRequestUrl().toString(),
                        String.valueOf(this.helpers.analyzeResponse(iHttpRequestResponse.getResponse()).getStatusCode()),
                        "[*] The shiro fingerprint identification of the site has exceeded the maximum limit, which can be modified in the configuration",
                        iHttpRequestResponse
                );
                return null;
            }
        }

        //判断当前站点加密key爆破成功次数是否超过了最大限制，这里设置的是1，也就是说该站点只要爆破出一个密钥就不对该站点进行探测了
        Integer keyFoundIssueMaxNumber = this.yamlReader.getInteger("webSite.shiroCipherKeyDetection.config.issueMaxNumber");
        if (keyFoundIssueMaxNumber > 0){
            String issueName = this.yamlReader.getString("webSite.shiroCipherKeyDetection.config.issueName");
            Integer issueNumber = this.getIssueNumber(customBurpReq, issueName);

            if (issueNumber > keyFoundIssueMaxNumber){
                this.tags.getScanQueueTag().add(
                        "",
                        "",
                        customBurpReq.getRequestMethod(),
                        customBurpReq.getRequestUrl().toString(),
                        String.valueOf(this.helpers.analyzeResponse(iHttpRequestResponse.getResponse()).getStatusCode()),
                        "[*] The shiro key identification of the site has exceeded the maximum limit, which can be modified in the configuration",
                        iHttpRequestResponse
                );
                return null;
            }

        }

        //开始指纹探测
        ShiroFingerprint shiroFinger = new ShiroFingerprint(callbacks, yamlReader, iHttpRequestResponse);
        IShiroFingerprintExtension shiroFingerprint = shiroFinger.getShiroFingerprint();

        //先判断指纹探测扩展是否开启
        if (!shiroFingerprint.isRunExtension()){
            this.tags.getScanQueueTag().add(
                    "",
                    "",
                    this.helpers.analyzeRequest(iHttpRequestResponse).getMethod(),
                    customBurpReq.getRequestUrl().toString(),
                    this.helpers.analyzeResponse(iHttpRequestResponse.getResponse()).getStatusCode() + "",
                    "[x] shiro fingerprint module startup error",
                    iHttpRequestResponse
            );
            return null;
        }

        //如果不是shiro站点
        if (!shiroFingerprint.isShiroFingerprint()){
            this.tags.getScanQueueTag().add(
                    "",
                    "",
                    this.helpers.analyzeRequest(iHttpRequestResponse).getMethod(),
                    customBurpReq.getRequestUrl().toString(),
                    this.helpers.analyzeResponse(iHttpRequestResponse.getResponse()).getStatusCode() + "",
                    "[-] the site is not a shiro framework",
                    iHttpRequestResponse
            );
            return null;
        }

        //如果是，则添加到issue以及console中
        issues.add(shiroFingerprint.export());

        shiroFingerprint.consoleExport();

        //添加到任务面板
        int tagId = this.tags.getScanQueueTag().add(
                shiroFingerprint.getExtensionName(),
                "",
                this.helpers.analyzeRequest(iHttpRequestResponse).getMethod(),
                customBurpReq.getRequestUrl().toString(),
                this.helpers.analyzeResponse(iHttpRequestResponse.getResponse()).getStatusCode() + "",
                "[+] found shiroFrameWork",
                shiroFingerprint.getHttpRequestResponse()
        );

        try {
            //shiro key检测开始
            GlobalPassiveScanVariableReader globalPassiveScanVariableReader = new GlobalPassiveScanVariableReader();

            Boolean isStartShiroCipherKeyExtension = this.tags.getBaseSettingsTag().isCipherKeyDetectionStart();
            //Boolean isStartShiroCipherKeyExtension = this.yamlReader.getBoolean("webSite.shiroCipherKeyDetection.config.isStart");
            Boolean isScanCbcEncrypt = this.yamlReader.getBoolean("webSite.shiroCipherKeyDetection.config.isScanCbcEncrypt");
            Boolean isScanGcmEncrypt = this.yamlReader.getBoolean("webSite.shiroCipherKeyDetection.config.isScanGcmEncrypt");

            if (isStartShiroCipherKeyExtension && (isScanCbcEncrypt || isScanGcmEncrypt)) {
                // 启动线程跑shiro加密key扩展任务
                String callClassName = this.yamlReader.getString("webSite.shiroCipherKeyDetection.config.provider");
                ShiroCipherKeyThread shiroCipherKeyThread = new ShiroCipherKeyThread(globalVariableReader, globalPassiveScanVariableReader,
                        callbacks, yamlReader, iHttpRequestResponse, shiroFinger, callClassName);

                //判断线程是否执行完毕
                while (true){
                    if (shiroCipherKeyThread.isTaskComplete()){
                        break;
                    }

                    Thread.sleep(500);
                }

                IShiroCipherKeyExtension shiroCipherKey = globalPassiveScanVariableReader.getShiroCipherKeyExtensionData("shiroCipherKey");

                // 为空的时候,表示没有成功爆破出shiro加密key
                if (shiroCipherKey == null){
                    this.tags.getScanQueueTag().save(
                            tagId,
                            "",
                            "",
                            this.helpers.analyzeRequest(iHttpRequestResponse).getMethod(),
                            customBurpReq.getRequestUrl().toString(),
                            this.helpers.analyzeResponse(iHttpRequestResponse.getResponse()).getStatusCode() + "",
                            "[-] not found shiro key",
                            iHttpRequestResponse);
                    return issues;
                }

                //反之则检测出了key
                IHttpRequestResponse shiroCipherKeyRequestResponse = shiroCipherKey.getHttpRequestResponse();
                this.tags.getScanQueueTag().save(
                        tagId,
                        shiroCipherKey.getExtensionName(),
                        shiroCipherKey.getEncryptMethod(),
                        this.helpers.analyzeRequest(shiroCipherKeyRequestResponse).getMethod(),
                        customBurpReq.getRequestUrl().toString(),
                        this.helpers.analyzeResponse(shiroCipherKeyRequestResponse.getResponse()).getStatusCode() + "",
                        "[+] found shiro key:" + shiroCipherKey.getCipherKey(),
                        shiroCipherKeyRequestResponse);

                // shiro加密key-控制台报告输出
                shiroCipherKey.consoleExport();

                // shiro加密key-报告输出
                issues.add(shiroCipherKey.export());
            }
        }catch (Exception e){
            //报错时清空指纹队列
            String shiroFingerprintIssueName = this.yamlReader.getString("webSite.shiroCipherKeyDetection.config.issueName");
            Integer shiroFingerprintIssueNumber = this.getSiteIssueNumber(customBurpReq.getRequestDomain(), shiroFingerprintIssueName);
            if (shiroFingerprintIssueNumber >= 1 && issues.size() >= 1) {
                issues.remove(0);
            }

            this.stdout.println(" ");
            this.stdout.println("========插件错误-未知错误============");
            this.stdout.println(String.format("url: %s", customBurpReq.getRequestUrl().toString()));
            this.stdout.println("错误详情请查看Extender里面对应插件的Errors标签页");
            this.stdout.println("========================================");
            this.stdout.println(" ");

            this.tags.getScanQueueTag().save(
                    tagId,
                    "",
                    "",
                    this.helpers.analyzeRequest(iHttpRequestResponse).getMethod(),
                    customBurpReq.getRequestUrl().toString(),
                    this.helpers.analyzeResponse(iHttpRequestResponse.getResponse()).getStatusCode() + "",
                    "[x] unknown error",
                    iHttpRequestResponse);

            e.printStackTrace(this.stderr);
        }
        return issues;
    }

    /**
     * 获取站点某一问题总个数
     * @param customBurpReq
     * @param issueName
     * @return
     */
    private Integer getIssueNumber(CustomBurpReq customBurpReq, String issueName) {
        IScanIssue[] scanIssues = this.callbacks.getScanIssues(customBurpReq.getRequestDomain());
        if (scanIssues.length == 0){
            return 0;
        }
        Integer number = 0;
        for (IScanIssue scanIssue : scanIssues) {
            if (scanIssue.getIssueName().equals(issueName)){
                number++;
            }
        }

        return number;
    }

    /**
     * 获取站点被扫描次数
     * @param customBurpReq
     * @return
     */
    private Integer getSiteMapNumber(CustomBurpReq customBurpReq) {
        IHttpRequestResponse[] siteMap = this.callbacks.getSiteMap(customBurpReq.getRequestDomain());
        Integer number = 0;
        for (IHttpRequestResponse iHttpRequestResponse : siteMap) {
                number++;
        }
        return number;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse iHttpRequestResponse, IScannerInsertionPoint iScannerInsertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue iScanIssue, IScanIssue iScanIssue1) {
        return 0;
    }


    /**
     * 判断是否匹配域名名单
     * @param domainName 待检测域名
     * @param domainNameList 域名黑/白名单
     * @return
     */
    private static Boolean isMatchDomainName(String domainName, List<String> domainNameList) {
        domainName = domainName.trim();

        if (domainName.length() <= 0) {
            return false;
        }

        if (domainNameList == null || domainNameList.size() <= 0) {
            return false;
        }

        if (domainName.contains(":")) {
            domainName = domainName.substring(0, domainName.indexOf(":"));
        }

        String reverseDomainName = new StringBuffer(domainName).reverse().toString();

        for (String domainName2 : domainNameList) {
            domainName2 = domainName2.trim();

            if (domainName2.length() <= 0) {
                continue;
            }

            if (domainName2.contains(":")) {
                domainName2 = domainName2.substring(0, domainName2.indexOf(":"));
            }

            String reverseDomainName2 = new StringBuffer(domainName2).reverse().toString();

            if (domainName.equals(domainName2)) {
                return true;
            }

            if (reverseDomainName.contains(".") && reverseDomainName2.contains(".")) {
                List<String> splitDomainName = new ArrayList<String>(Arrays.asList(reverseDomainName.split("[.]")));

                List<String> splitDomainName2 = new ArrayList<String>(Arrays.asList(reverseDomainName2.split("[.]")));

                if (splitDomainName.size() <= 0 || splitDomainName2.size() <= 0) {
                    continue;
                }

                if (splitDomainName.size() < splitDomainName2.size()) {
                    for (int i = splitDomainName.size(); i < splitDomainName2.size(); i++) {
                        splitDomainName.add("*");
                    }
                }

                if (splitDomainName.size() > splitDomainName2.size()) {
                    for (int i = splitDomainName2.size(); i < splitDomainName.size(); i++) {
                        splitDomainName2.add("*");
                    }
                }

                int ii = 0;
                for (int i = 0; i < splitDomainName.size(); i++) {
                    if (splitDomainName2.get(i).equals("*")) {
                        ii = ii + 1;
                    } else if (splitDomainName.get(i).equals(splitDomainName2.get(i))) {
                        ii = ii + 1;
                    }
                }

                if (ii == splitDomainName.size()) {
                    return true;
                }
            }
        }
        return false;
    }

    public boolean isUrlBlackListSuffix(CustomBurpReq customBurpReq){
        if (!this.yamlReader.getBoolean("scan.urlSuffix.config.isStart")){
            return false;
        }

        String requestUri = customBurpReq.getRequestUri();
        String suffix = requestUri.substring(requestUri.lastIndexOf(".")+1);

        List<String> blackList = this.yamlReader.getStringList("scan.urlSuffix.blackList");

        if (blackList == null || blackList.size() == 0){
            return false;
        }

        for (String s : blackList) {
            if (s.toLowerCase().equals(suffix.toLowerCase())){
                return true;
            }
        }
        return false;
    }

    /**
     * 网站问题数量
     *
     * @param domainName 请求域名名称
     * @param issueName  要查询的问题名称
     * @return
     */
    private Integer getSiteIssueNumber(String domainName, String issueName) {
        Integer number = 0;

        for (IScanIssue Issue : this.callbacks.getScanIssues(domainName)) {
            if (Issue.getIssueName().equals(issueName)) {
                number++;
            }
        }

        return number;
    }
}
