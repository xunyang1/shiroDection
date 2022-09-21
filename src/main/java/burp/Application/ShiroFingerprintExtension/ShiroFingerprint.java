package burp.Application.ShiroFingerprintExtension;

import burp.Application.ShiroFingerprintExtension.ExtensionInterface.IShiroFingerprintExtension;
import burp.Application.ShiroFingerprintExtension.ExtensionMethod.ShiroFingerprint1;
import burp.Application.ShiroFingerprintExtension.ExtensionMethod.ShiroFingerprint2;
import burp.Application.ShiroFingerprintExtension.ExtensionMethod.ShiroFingerprint3;
import burp.Bootstrap.YamlReader;
import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;

public class ShiroFingerprint {
    private IBurpExtenderCallbacks callbacks;
    private YamlReader yamlReader;
    private IHttpRequestResponse baseRequestResponse;

    private IShiroFingerprintExtension shiroFingerprint;


    public ShiroFingerprint(IBurpExtenderCallbacks callbacks, YamlReader yamlReader, IHttpRequestResponse baseRequestResponse) {
        this.callbacks = callbacks;
        this.yamlReader = yamlReader;
        this.baseRequestResponse = baseRequestResponse;

        this.shiroFingerprint = setShiroFingerprint();

    }

    private IShiroFingerprintExtension setShiroFingerprint() {
        //根据baseRequestResponse判断选择哪个shiro指纹检测扩展

        //原始请求cooike中带了rememberMe则进入该扩展
        ShiroFingerprint3 shiroFingerprint3 = new ShiroFingerprint3(this.callbacks, this.yamlReader, this.baseRequestResponse);
        if (shiroFingerprint3.isRunExtension()){
            shiroFingerprint3.RunExtension();
            return shiroFingerprint3;
        }

        //原始请求的响应cooike中带了deleteMe则进入该扩展
        ShiroFingerprint2 shiroFingerprint2 = new ShiroFingerprint2(this.callbacks, this.yamlReader, this.baseRequestResponse);
        if (shiroFingerprint2.isRunExtension()){
            shiroFingerprint2.RunExtension();
            return shiroFingerprint2;
        }

        //以上两个都不满足则进入该扩展，自定义构造
        ShiroFingerprint1 shiroFingerprint1 = new ShiroFingerprint1(this.callbacks, this.yamlReader, this.baseRequestResponse);
        if (shiroFingerprint1.isRunExtension()){
            shiroFingerprint1.RunExtension();
            return shiroFingerprint1;
        }
        return null;
    }

    public IShiroFingerprintExtension getShiroFingerprint() {
        return shiroFingerprint;
    }
}
