package burp.Bootstrap;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;

import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;

public class CustomBurpReq {
    private IExtensionHelpers helpers;

    private IHttpRequestResponse requestResponse;
    private PrintWriter stderr;


    public CustomBurpReq(IBurpExtenderCallbacks callbacks, IHttpRequestResponse requestResponse) {
        this.helpers = callbacks.getHelpers();
        this.requestResponse = requestResponse;
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
    }

    /**
     * 获取请求方式
     * @return
     */
    public String getRequestMethod(){
        return this.helpers.analyzeRequest(requestResponse).getMethod();
    }

    /**
     * 获取请求协议
     * @return
     */
    public String getRequestProtocol(){
         return requestResponse.getHttpService().getProtocol();
    }

    /**
     * 获取请求域名
     * @return
     */
    public String getRequestHost(){
        return requestResponse.getHttpService().getHost();
    }

    /**
     * 获取请求端口
     * @return
     */
    public int getRequestPort(){
        return requestResponse.getHttpService().getPort();
    }

    /**
     * 获取请求协议+域名+端口
     * @return
     */
    public String getRequestDomain(){
        if (this.getRequestPort() == 80 || this.getRequestPort() == 443){
            return this.getRequestProtocol()+"://"+this.getRequestHost();
        }else {
            return this.getRequestProtocol()+"://"+this.getRequestHost()+":"+this.getRequestPort();
        }
    }

    /**
     * 获取请求url
     * @return
     */
    public String getRequestUri(){
        return this.helpers.analyzeRequest(this.requestResponse).getUrl().getPath();
    }

    /**
     * 获取请求参数
     * @return
     */
    public String getRequestParam(){
        return this.helpers.analyzeRequest(this.requestResponse).getUrl().getQuery();
    }

    /**
     * 获取完整请求url
     * @return
     */
    public URL getRequestUrl(){
        try {
            if (this.getRequestParam() == null){
                return new URL(this.getRequestDomain()+this.getRequestUri());
            }else {
                return new URL(this.getRequestDomain()+this.getRequestUri()+"?"+this.getRequestParam());
            }
        }catch (MalformedURLException e){
            e.printStackTrace(this.stderr);
        }
        return null;
    }





}
